const std = @import("std");
const os = std.os;
const fmt = std.fmt;

const packet = @import("packet.zig");
const proto = @import("proto.zig");
const resolv = @import("resolvconf.zig");

const DNSPacket = packet.DNSPacket;

test "zigdig" {
    _ = @import("packet.zig");
    _ = @import("proto.zig");
    _ = @import("resolvconf.zig");
}

fn resolve(addr: std.net.Address, pkt: DNSPacket) !bool {
    var sockfd = try proto.openDNSSocket(addr);
    errdefer std.os.close(sockfd);

    var buf: [5000]u8 = undefined;

    try proto.sendDNSPacket(sockfd, pkt, &buf);
    var recv_pkt = try proto.recvDNSPacket(sockfd, &buf);
    std.debug.warn("{}\n", recv_pkt.as_str());

    // TODO: complete, check errors, etc

    return true;
}

fn makeDNSPacket(
    allocator: *std.mem.Allocator,
    name: []u8,
    qtype: []u8,
) !DNSPacket {
    var qtype_i = try fmt.parseInt(u8, qtype, 10);
    var pkt = DNSPacket.init(allocator);

    var question = packet.DNSQuestion{
        .qname = packet.DNSName{
            .len = @intCast(u8, name.len),
            .value = name,
        },

        // TODO: add a DNSType enum and conversions between them
        .qtype = qtype_i,

        // TODO: add a DNSClass enum
        .qclass = 1,
    };

    try pkt.addQuestion(question);
    return pkt;
}

pub fn main() anyerror!void {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();

    const allocator = &arena.allocator;
    var args_it = os.args();

    _ = args_it.skip();

    const name = try (args_it.next(allocator) orelse {
        std.debug.warn("no name provided\n");
        return error.InvalidArgs;
    });

    const qtype = try (args_it.next(allocator) orelse {
        std.debug.warn("no qtype provided\n");
        return error.InvalidArgs;
    });

    std.debug.warn("{} {}\n", name, qtype);

    var pkt = try makeDNSPacket(allocator, name, qtype);

    std.debug.warn("packet: {}\n", pkt.as_str());

    // read /etc/resolv.conf for nameserver
    var nameservers = try resolv.readNameservers();

    for (nameservers) |nameserver| {
        if (nameserver[0] == 0) continue;
        std.debug.warn("nameserver '{}'\n", nameserver);

        // TODO: ipv6 address support
        var ip4addr = try std.net.parseIp4("127.0.0.1");
        var addr = std.net.Address.initIp4(ip4addr, 36953);

        if (try resolve(addr, pkt)) break;
    }
}
