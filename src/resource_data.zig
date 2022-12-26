const std = @import("std");
const fmt = std.fmt;

const dns = @import("./lib.zig");
const pkt = @import("./packet.zig");
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
    pub fn format(
        self: Self,
        comptime f: []const u8,
        options: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = f;
        _ = options;

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

            .TXT => |text| return fmt.format(writer, "{s}", .{text}),
            else => return fmt.format(writer, "TODO support {s}", .{@tagName(self)}),
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

    /// Only call this if you dynamically created a ResourceData
    /// through the fromOpaque() method.
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| name.deinit(allocator),
            .SOA => |soa_data| {
                soa_data.mname.deinit(allocator);
                soa_data.rname.deinit(allocator);
            },
            .MX => |mxdata| mxdata.exchange.deinit(allocator),
            .SRV => |srv| srv.target.deinit(allocator),
            .TXT => |data| allocator.free(data),
            else => {},
        }
    }

    pub const Opaque = struct {
        data: []const u8,
        current_byte_count: usize,
    };

    /// Deserialize a given opaque resource data.
    ///
    /// Call deinit() with the same allocator.
    pub fn fromOpaque(
        /// Packet the resource data comes from.
        ///
        /// This is required as resource data may have name pointers
        /// that refer to the packet index.
        packet: dns.Packet,
        typ: dns.ResourceType,
        opaque_resource_data: Opaque,
        allocator: std.mem.Allocator,
    ) !ResourceData {
        const BufferT = std.io.FixedBufferStream([]const u8);
        var stream = BufferT{ .buffer = opaque_resource_data.data, .pos = 0 };
        var underlying_reader = stream.reader();

        // important to keep track of that rdata's position in the packet
        // as rdata could point to other rdata.

        var ctx = pkt.DeserializationContext{
            .current_byte_count = opaque_resource_data.current_byte_count,
        };
        const WrapperR = pkt.WrapperReader(BufferT.Reader);
        var wrapper_reader = WrapperR.init(underlying_reader, &ctx);
        var reader = wrapper_reader.reader();

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

            .NS => ResourceData{ .NS = try packet.readName(reader, allocator, .{}) },
            .CNAME => ResourceData{ .CNAME = try packet.readName(reader, allocator, .{}) },
            .PTR => ResourceData{ .PTR = try packet.readName(reader, allocator, .{}) },
            .MD => ResourceData{ .MD = try packet.readName(reader, allocator, .{}) },
            .MF => ResourceData{ .MF = try packet.readName(reader, allocator, .{}) },

            .MX => blk: {
                break :blk ResourceData{
                    .MX = MXData{
                        .preference = try reader.readIntBig(u16),
                        .exchange = try packet.readName(reader, allocator, .{}),
                    },
                };
            },

            .SOA => blk: {
                var mname = try packet.readName(reader, allocator, .{});
                var rname = try packet.readName(reader, allocator, .{});
                var serial = try reader.readIntBig(u32);
                var refresh = try reader.readIntBig(u32);
                var retry = try reader.readIntBig(u32);
                var expire = try reader.readIntBig(u32);
                var minimum = try reader.readIntBig(u32);

                break :blk ResourceData{
                    .SOA = SOAData{
                        .mname = mname,
                        .rname = rname,
                        .serial = serial,
                        .refresh = refresh,
                        .retry = retry,
                        .expire = expire,
                        .minimum = minimum,
                    },
                };
            },
            .SRV => blk: {
                const priority = try reader.readIntBig(u16);
                const weight = try reader.readIntBig(u16);
                const port = try reader.readIntBig(u16);
                const target = try packet.readName(reader, allocator, .{});
                break :blk ResourceData{
                    .SRV = .{
                        .priority = priority,
                        .weight = weight,
                        .port = port,
                        .target = target,
                    },
                };
            },
            .TXT => blk: {
                const length = try reader.readIntBig(u8);
                if (length > 256) return error.Overflow;

                var text = try allocator.alloc(u8, length);
                _ = try reader.read(text);

                break :blk ResourceData{ .TXT = text };
            },

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
