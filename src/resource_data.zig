const std = @import("std");
const fmt = std.fmt;

const dns = @import("./lib.zig");
const Type = dns.ResourceType;

pub const SOAData = struct {
    mname: dns.Name,
    rname: dns.Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const MXData = struct {
    preference: u16,
    exchange: dns.Name,
};

pub const SRVData = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: dns.Name,
};

/// Common representations of DNS' Resource Data.
pub const ResourceData = union(Type) {
    A: std.net.Address,
    AAAA: std.net.Address,

    NS: dns.Name,
    MD: dns.Name,
    MF: dns.Name,
    CNAME: dns.Name,
    SOA: SOAData,

    MB: dns.Name,
    MG: dns.Name,
    MR: dns.Name,

    // ????
    NULL: void,

    // TODO WKS bit map
    WKS: struct {
        addr: u32,
        proto: u8,
        // how to define bit map? align(8)?
    },
    PTR: dns.Name,

    // TODO replace by Name?
    HINFO: struct {
        cpu: []const u8,
        os: []const u8,
    },
    MINFO: struct {
        rmailbx: dns.Name,
        emailbx: dns.Name,
    },
    MX: MXData,
    TXT: []const u8,

    SRV: SRVData,

    const Self = @This();

    pub fn networkSize(self: Self) usize {
        return switch (self) {
            .A => 4,
            .AAAA => 16,
            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| name.size(),
            .TXT => |text| blk: {
                var len: usize = 0;
                len += @sizeOf(u16) * text.len;
                for (text) |string| {
                    len += string.len;
                }
                break :blk len;
            },

            else => @panic("TODO"),
        };
    }

    /// Format the RData into a human-readable form of it.
    ///
    /// For example, a resource data of type A would be
    /// formatted to its representing IPv4 address.
    pub fn format(self: Self, comptime f: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        if (f.len != 0) {
            @compileError("Unknown format character: '" ++ f ++ "'");
        }

        switch (self) {
            .A, .AAAA => |addr| return fmt.format(writer, "{}", .{addr}),

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| return fmt.format(writer, "{}", .{name}),

            .SOA => |soa| return fmt.format(writer, "{} {} {} {} {} {} {}", .{
                soa.mname,
                soa.rname,
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
            }),

            .MX => |mx| return fmt.format(writer, "{} {}", .{ mx.preference, mx.exchange }),
            .SRV => |srv| return fmt.format(writer, "{} {} {} {}", .{
                srv.priority,
                srv.weight,
                srv.port,
                srv.target,
            }),

            .TXT => |text| return fmt.format(writer, "{}", .{text}),
            else => return fmt.format(writer, "TODO support {}", .{@tagName(self)}),
        }
    }

    pub fn writeTo(self: Self, writer: anytype) !usize {
        return switch (self) {
            .A => |addr| blk: {
                try writer.writeIntBig(u32, addr.in.sa.addr);
                break :blk @sizeOf(@TypeOf(addr.in.sa.addr));
            },
            .AAAA => |addr| try writer.write(&addr.in6.sa.addr),

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| try name.writeTo(writer),

            .SOA => |soa_data| blk: {
                const mname_size = try soa_data.mname.writeTo(writer);
                const rname_size = try soa_data.rname.writeTo(writer);

                try writer.writeIntBig(u32, soa_data.serial);
                try writer.writeIntBig(u32, soa_data.refresh);
                try writer.writeIntBig(u32, soa_data.retry);
                try writer.writeIntBig(u32, soa_data.expire);
                try writer.writeIntBig(u32, soa_data.minimum);

                break :blk mname_size + rname_size + (5 * @sizeOf(u32));
            },

            .MX => |mxdata| blk: {
                try writer.writeIntBig(u16, mxdata.preference);
                const exchange_size = try mxdata.exchange.writeTo(writer);
                break :blk @sizeOf(@TypeOf(mxdata.preference)) + exchange_size;
            },

            .SRV => |srv| {
                try writer.writeIntBig(u16, srv.priority);
                try writer.writeIntBig(u16, srv.weight);
                try writer.writeIntBig(u16, srv.port);

                const target_size = try srv.target.writeTo(writer);
                return target_size + (3 * @sizeOf(u16));
            },

            else => @panic("not implemented"),
        };
    }

    /// Deserialize a given opaque resource data.
    pub fn fromOpaque(
        typ: dns.ResourceType,
        opaque_resource_data: []const u8,
    ) !ResourceData {
        const BufferT = std.io.FixedBufferStream([]const u8);
        var stream = BufferT{ .buffer = opaque_resource_data, .pos = 0 };
        var reader = stream.reader();

        var rdata = switch (typ) {
            .A => blk: {
                var ip4addr: [4]u8 = undefined;
                _ = try reader.read(&ip4addr);
                break :blk ResourceData{
                    .A = std.net.Address.initIp4(ip4addr, 0),
                };
            },
            .AAAA => blk: {
                var ip6_addr: [16]u8 = undefined;
                _ = try reader.read(&ip6_addr);
                break :blk ResourceData{
                    .AAAA = std.net.Address.initIp6(ip6_addr, 0, 0, 0),
                };
            },

            //.NS => ResourceData{ .NS = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null) },
            //.CNAME => ResourceData{ .CNAME = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null) },
            //.PTR => ResourceData{ .PTR = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null) },
            //.MX => blk: {
            //    break :blk ResourceData{
            //        .MX = MXData{
            //            .preference = try deserializer.deserialize(u16),
            //            .exchange = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null),
            //        },
            //    };
            //},
            // .MD => ResourceData{ .MD = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null) },
            // .MF => ResourceData{ .MF = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null) },

            // .SOA => blk: {
            //     var mname = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null);
            //     var rname = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null);
            //     var serial = try deserializer.deserialize(u32);
            //     var refresh = try deserializer.deserialize(u32);
            //     var retry = try deserializer.deserialize(u32);
            //     var expire = try deserializer.deserialize(u32);
            //     var minimum = try deserializer.deserialize(u32);

            //     break :blk ResourceData{
            //         .SOA = SOAData{
            //             .mname = mname,
            //             .rname = rname,
            //             .serial = serial,
            //             .refresh = refresh,
            //             .retry = retry,
            //             .expire = expire,
            //             .minimum = minimum,
            //         },
            //     };
            // },
            // .SRV => blk: {
            //     const priority = try deserializer.deserialize(u16);
            //     const weight = try deserializer.deserialize(u16);
            //     const port = try deserializer.deserialize(u16);
            //     var target = try dns.Packet.readName(&deserializer, ctx, try createNameBuffer(ctx), null);

            //     break :blk ResourceData{
            //         .SRV = .{
            //             .priority = priority,
            //             .weight = weight,
            //             .port = port,
            //             .target = target,
            //         },
            //     };
            // },
            // .TXT => blk: {
            //     var txt_buffer = try ctx.allocator.alloc(u8, 256);
            //     try ctx.label_pool.append(txt_buffer);

            //     const length = try deserializer.deserialize(u8);
            //     var idx: usize = 0;
            //     while (idx < length) : (idx += 1) {
            //         txt_buffer[idx] = try deserializer.deserialize(u8);
            //     }

            //     break :blk ResourceData{ .TXT = txt_buffer[0..idx] };
            // },

            else => {
                logger.warn("unexpected rdata: {}\n", .{typ});
                return error.InvalidRData;
            },
        };

        return rdata;
    }
};

const logger = std.log.scoped(.dns_rdata);

fn createNameBuffer(ctx: *dns.DeserializationContext) ![][]const u8 {
    // TODO should we just keep this hardcoded? how could we better manage those
    // name buffers?
    var name_buffer = try ctx.allocator.alloc([]const u8, 128);
    try ctx.name_pool.append(name_buffer);
    return name_buffer;
}
