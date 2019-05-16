// DNS RDATA understanding (parsing etc)
const std = @import("std");
const io = std.io;

const types = @import("types.zig");
const packet = @import("packet.zig");

const DNSRData = union(types.DNSType) {
    A: u32,
    AAAA: std.net.Ip6Addr,
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

/// Parse a given OpaqueDNSRData into a DNSRData.
pub fn parseRData(
    packet: packet.DNSPacket,
    opaque: packet.OpaqueDNSRData,
) !DNSRData {
    // TODO
}
