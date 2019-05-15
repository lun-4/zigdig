const std = @import("std");
const os = std.os;
const fmt = std.fmt;

const packet = @import("packet.zig");
const proto = @import("proto.zig");
const resolv = @import("resolvconf.zig");

const DNSPacket = packet.DNSPacket;
const Allocator = std.mem.Allocator;

test "zigdig" {
    _ = @import("packet.zig");
    _ = @import("proto.zig");
    _ = @import("resolvconf.zig");
}

fn resolve(allocator: *Allocator, addr: std.net.Address, pkt: DNSPacket) !bool {
    var sockfd = try proto.openDNSSocket(addr);
    errdefer std.os.close(sockfd);

    var buf = try allocator.alloc(u8, pkt.size());

    // TODO: better values here
    var recvbuf = try allocator.alloc(u8, 0x10000);
    var recvpkt = try packet.DNSPacket.init(allocator);

    try proto.sendDNSPacket(sockfd, pkt, buf);
    try proto.recvDNSPacket(sockfd, recvbuf, &recvpkt);
    std.debug.warn("{}\n", recvpkt.as_str());

    // TODO: complete, check errors, etc

    return true;
}

fn makeDNSPacket(
    allocator: *std.mem.Allocator,
    name: []u8,
    qtype: []u8,
) !DNSPacket {
    var qtype_i = try fmt.parseInt(u8, qtype, 10);
    var pkt = try DNSPacket.init(allocator);

    // set random u16 as the id + all the other goodies in the header
    var r = std.rand.DefaultPrng.init(std.os.time.timestamp());
    const random_id = r.random.int(u16);
    pkt.header.id = random_id;
    pkt.header.rd = true;

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
        //var ip4addr = try std.net.parseIp4("127.0.0.1");
        //var addr = std.net.Address.initIp4(ip4addr, 36953);
        var ip4addr = try std.net.parseIp4(nameserver);
        var addr = std.net.Address.initIp4(ip4addr, 53);

        if (try resolve(allocator, addr, pkt)) break;
    }
}
