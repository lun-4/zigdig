const std = @import("std");
const fmt = std.fmt;

const dns = @import("./lib.zig");
const pkt = @import("./packet.zig");
const Type = dns.ResourceType;

const logger = std.log.scoped(.dns_rdata);

pub const SOAData = struct {
    mname: ?dns.Name,
    rname: ?dns.Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

pub const MXData = struct {
    preference: u16,
    exchange: ?dns.Name,
};

pub const SRVData = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: ?dns.Name,
};

fn maybeReadResourceName(
    reader: anytype,
    options: ResourceData.ParseOptions,
) !?dns.Name {
    return switch (options.name_provider) {
        .none => null,
        .raw => |allocator| try dns.Name.readFrom(reader, .{ .allocator = allocator }),
        .full => |name_pool| blk: {
            var name = try dns.Name.readFrom(
                reader,
                .{ .allocator = name_pool.allocator },
            );
            break :blk try name_pool.transmuteName(name.?);
        },
    };
}

/// Common representations of DNS' Resource Data.
pub const ResourceData = union(Type) {
    A: std.net.Address,

    NS: ?dns.Name,
    MD: ?dns.Name,
    MF: ?dns.Name,
    CNAME: ?dns.Name,
    SOA: SOAData,

    MB: ?dns.Name,
    MG: ?dns.Name,
    MR: ?dns.Name,

    // ????
    NULL: void,

    // TODO WKS bit map
    WKS: struct {
        addr: u32,
        proto: u8,
        // how to define bit map? align(8)?
    },
    PTR: ?dns.Name,

    // TODO replace []const u8 by Name?
    HINFO: struct {
        cpu: []const u8,
        os: []const u8,
    },
    MINFO: struct {
        rmailbx: ?dns.Name,
        emailbx: ?dns.Name,
    },
    MX: MXData,
    TXT: ?[]const u8,
    AAAA: std.net.Address,
    SRV: SRVData,
    OPT: void, // EDNS0 is not implemented

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

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| return fmt.format(writer, "{?}", .{name}),

            .SOA => |soa| return fmt.format(writer, "{?} {?} {} {} {} {} {}", .{
                soa.mname,
                soa.rname,
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
            }),

            .MX => |mx| return fmt.format(writer, "{} {?}", .{ mx.preference, mx.exchange }),
            .SRV => |srv| return fmt.format(writer, "{} {} {} {?}", .{
                srv.priority,
                srv.weight,
                srv.port,
                srv.target,
            }),

            .TXT => |text| return fmt.format(writer, "{?s}", .{text}),
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

            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |name| try name.?.writeTo(writer),

            .SOA => |soa_data| blk: {
                const mname_size = try soa_data.mname.?.writeTo(writer);
                const rname_size = try soa_data.rname.?.writeTo(writer);

                try writer.writeIntBig(u32, soa_data.serial);
                try writer.writeIntBig(u32, soa_data.refresh);
                try writer.writeIntBig(u32, soa_data.retry);
                try writer.writeIntBig(u32, soa_data.expire);
                try writer.writeIntBig(u32, soa_data.minimum);

                break :blk mname_size + rname_size + (5 * @sizeOf(u32));
            },

            .MX => |mxdata| blk: {
                try writer.writeIntBig(u16, mxdata.preference);
                const exchange_size = try mxdata.exchange.?.writeTo(writer);
                break :blk @sizeOf(@TypeOf(mxdata.preference)) + exchange_size;
            },

            .SRV => |srv| {
                try writer.writeIntBig(u16, srv.priority);
                try writer.writeIntBig(u16, srv.weight);
                try writer.writeIntBig(u16, srv.port);

                const target_size = try srv.target.?.writeTo(writer);
                return target_size + (3 * @sizeOf(u16));
            },

            // TODO TXT

            else => @panic("not implemented"),
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .NS, .MD, .MF, .MB, .MG, .MR, .CNAME, .PTR => |maybe_name| if (maybe_name) |name| name.deinit(allocator),
            .SOA => |soa_data| {
                if (soa_data.mname) |name| name.deinit(allocator);
                if (soa_data.rname) |name| name.deinit(allocator);
            },
            .MX => |mxdata| if (mxdata.exchange) |name| name.deinit(allocator),
            .SRV => |srv| if (srv.target) |name| name.deinit(allocator),
            .TXT => |maybe_data| if (maybe_data) |data| allocator.free(data),
            else => {},
        }
    }

    pub const Opaque = struct {
        data: []const u8,
        current_byte_count: usize,
    };

    pub const NameProvider = union(enum) {
        none: void,
        raw: std.mem.Allocator,
        full: *dns.NamePool,
    };

    pub const ParseOptions = struct {
        name_provider: NameProvider = NameProvider.none,
        allocator: ?std.mem.Allocator = null,
    };

    /// Deserialize a given opaque resource data.
    ///
    /// Call deinit() with the same allocator.
    pub fn fromOpaque(
        resource_type: dns.ResourceType,
        opaque_resource_data: Opaque,
        options: ParseOptions,
    ) !ResourceData {
        const BufferT = std.io.FixedBufferStream([]const u8);
        var stream = BufferT{ .buffer = opaque_resource_data.data, .pos = 0 };
        var underlying_reader = stream.reader();

        // important to keep track of that rdata's position in the packet
        // as rdata could point to other rdata.
        var parser_ctx = dns.ParserContext{
            .current_byte_count = opaque_resource_data.current_byte_count,
        };

        const WrapperR = dns.parserlib.WrapperReader(BufferT.Reader);
        var wrapper_reader = WrapperR{
            .underlying_reader = underlying_reader,
            .ctx = &parser_ctx,
        };
        var reader = wrapper_reader.reader();

        return switch (resource_type) {
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

            .NS => ResourceData{ .NS = try maybeReadResourceName(reader, options) },
            .CNAME => ResourceData{ .CNAME = try maybeReadResourceName(reader, options) },
            .PTR => ResourceData{ .PTR = try maybeReadResourceName(reader, options) },
            .MD => ResourceData{ .MD = try maybeReadResourceName(reader, options) },
            .MF => ResourceData{ .MF = try maybeReadResourceName(reader, options) },

            .MX => blk: {
                break :blk ResourceData{
                    .MX = MXData{
                        .preference = try reader.readIntBig(u16),
                        .exchange = try maybeReadResourceName(reader, options),
                    },
                };
            },

            .SOA => blk: {
                var mname = try maybeReadResourceName(reader, options);
                var rname = try maybeReadResourceName(reader, options);
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
                const target = try maybeReadResourceName(reader, options);
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

                if (options.allocator) |allocator| {
                    var text = try allocator.alloc(u8, length);
                    _ = try reader.read(text);

                    break :blk ResourceData{ .TXT = text };
                } else {
                    try reader.skipBytes(length, .{});
                    break :blk ResourceData{ .TXT = null };
                }
            },

            else => {
                logger.warn("unexpected rdata: {}\n", .{resource_type});
                return error.UnknownResourceType;
            },
        };
    }
};
