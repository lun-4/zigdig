// DNS RDATA understanding (parsing etc)
const std = @import("std");
const io = std.io;

const types = @import("types.zig");
const packet = @import("packet.zig");
const err = @import("error.zig");

const DNSError = err.DNSError;
const InError = io.SliceInStream.Error;
const OutError = io.SliceOutStream.Error;
const DNSType = types.DNSType;

/// DNS RDATA representation to a "native-r" type for nicer usage.
const DNSRData = union(types.DNSType) {
    A: std.net.Address,

    // TODO: move this to std.net.Address once the stdlib has fixes
    // for ipv6 storage & unparsing.
    AAAA: [16]u8,
    NS: packet.DNSName,
    MD: packet.DNSName,
    MF: packet.DNSName,
    CNAME: packet.DNSName,
    SOA: struct {
        mname: packet.DNSName,
        rname: packet.DNSName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    MB: packet.DNSName,
    MG: packet.DNSName,
    MR: packet.DNSName,

    // ????
    NULL: void,

    // TODO
    WKS: struct {
        addr: u32,
        proto: u8,
        // how to define bit map? align(8)?
    },
    PTR: packet.DNSName,
    HINFO: struct {
        cpu: []const u8,
        os: []const u8,
    },
    MINFO: struct {
        rmailbx: packet.DNSName,
        emailbx: packet.DNSName,
    },
    MX: struct {
        preference: u16,
        exchange: packet.DNSName,
    },
    TXT: [][]const u8,
};

/// Parse a given OpaqueDNSRData into a DNSRData. Requires the original
/// DNSPacket for allocator purposes and the original DNSResource for
/// TYPE detection.
pub fn parseRData(
    pkt_const: packet.DNSPacket,
    resource: packet.DNSResource,
    opaque: packet.OpaqueDNSRData,
) !DNSRData {
    var pkt = pkt_const;

    var opaque_val = opaque.value;
    var in = io.SliceInStream.init(opaque_val);
    var in_stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);

    var rdata_enum = @intToEnum(DNSType, resource.rr_type);

    var rdata = switch (rdata_enum) {
        .A => blk: {
            var addr = try deserializer.deserialize(u32);
            break :blk DNSRData{ .A = std.net.Address.initIp4(addr, 53) };
        },
        .AAAA => blk: {
            var ip6_addr: [16]u8 = undefined;

            for (ip6_addr) |byte, i| {
                ip6_addr[i] = try deserializer.deserialize(u8);
            }

            break :blk DNSRData{ .AAAA = ip6_addr };
        },

        .NS => DNSRData{ .NS = try pkt.deserializeName(&deserializer) },
        .CNAME => DNSRData{ .CNAME = try pkt.deserializeName(&deserializer) },
        .PTR => DNSRData{ .PTR = try pkt.deserializeName(&deserializer) },

        else => blk: {
            return DNSError.RDATANotSupported;
        },
    };

    return rdata;
}

fn printName(
    stream: *std.io.OutStream(OutError),
    name: packet.DNSName,
) !void {
    for (name.labels) |label| {
        try stream.print("{}", label);
        try stream.print(".");
    }
}

/// Prettify a given DNSRData union variable. Returns a string with e.g
/// a string representation of an ipv4 address, or the human-readable version
/// of a DNSName.
pub fn prettyRData(allocator: *std.mem.Allocator, rdata: DNSRData) ![]const u8 {
    var buf = try allocator.alloc(u8, 256);

    var out = io.SliceOutStream.init(buf);
    var stream = &out.stream;

    switch (rdata) {
        DNSType.A => blk: {
            var d = rdata.A.os_addr.in.addr;
            var v1 = d & 0xff;
            var v2 = (d >> 8) & 0xff;
            var v3 = (d >> 16) & 0xff;
            var v4 = (d >> 24);
            try stream.print("{}.{}.{}.{}", v4, v3, v2, v1);
            break :blk;
        },

        DNSType.AAAA => blk: {
            var prev_zero: bool = false;
            for (rdata.AAAA) |byte| {
                if (prev_zero and byte == 0) {
                    // if previous byte was 0 (and we're also 0)
                    // we shouldn't need to do anything
                } else {
                    try stream.print(":");
                    if (byte == 0) {
                        prev_zero = true;
                        continue;
                    }
                    try stream.print("{x}", byte);
                }
            }
            break :blk;
        },

        .CNAME => try printName(stream, rdata.CNAME),
        .NS => try printName(stream, rdata.NS),
        .PTR => try printName(stream, rdata.PTR),

        // TODO: DNSName deserialization
        else => try stream.write("unsupported rdata"),
    }

    return buf[0..];
}
