const std = @import("std");
const os = std.os;
const fmt = std.fmt;

const packet = @import("packet.zig");
const proto = @import("proto.zig");
const resolv = @import("resolvconf.zig");
const types = @import("types.zig");
const rdata = @import("rdata.zig");

const DNSPacket = packet.DNSPacket;
const DNSPacketRCode = packet.DNSPacketRCode;
const Allocator = std.mem.Allocator;

const MainDNSError = error{
    UnknownReplyId,
    GotQuestion,
    RCodeErr,
};

test "zigdig" {
    _ = @import("packet.zig");
    _ = @import("proto.zig");
    _ = @import("resolvconf.zig");
}

fn printPacket(pkt: DNSPacket) !void {
    std.debug.warn(
        "id: {}, opcode: {}, rcode: {}\n",
        pkt.header.id,
        pkt.header.opcode,
        pkt.header.rcode,
    );

    std.debug.warn(
        "qd: {}, an: {}, ns: {}, ar: {}\n\n",
        pkt.header.qdcount,
        pkt.header.ancount,
        pkt.header.nscount,
        pkt.header.arcount,
    );

    if (pkt.header.qdcount > 0) {
        std.debug.warn(";;-- question --\n");
        std.debug.warn(";;qname\t\tqtype\tqclass\n");

        for (pkt.questions) |question| {
            std.debug.warn(
                "{}.\t{}\t{}\n",
                packet.nameToStr(pkt.allocator, question.qname),
                types.typeToStr(question.qtype),
                question.qclass,
            );
        }

        std.debug.warn("\n");
    }

    if (pkt.header.ancount > 0) {
        std.debug.warn(";; -- answer --\n");
        std.debug.warn(";;name\t\trrtype\tclass\tttl\trdata\n");

        for (pkt.answers) |answer| {

            // TODO: convert rr_type to better []u8 representation, same for
            // class (IN and A, and etc)
            var pkt_rdata = try rdata.parseRData(pkt, answer, answer.rdata);
            var buf: [255]u8 = undefined;

            std.debug.warn(
                "{}.\t{}\t{}\t{}\t{}\n",
                try packet.nameToStr(pkt.allocator, answer.name),
                types.typeToStr(answer.rr_type),
                answer.class,
                answer.ttl,
                try rdata.prettyRData(pkt_rdata, buf[0..]),
            );
        }
    }
}

fn resolve(allocator: *Allocator, addr: std.net.Address, pkt: DNSPacket) !bool {
    var sockfd = try proto.openDNSSocket(addr);
    errdefer std.os.close(sockfd);

    var buf = try allocator.alloc(u8, pkt.size());

    try proto.sendDNSPacket(sockfd, pkt, buf);

    var recvpkt = try proto.recvDNSPacket(sockfd, allocator);

    std.debug.warn("recv packet: {}\n", recvpkt.as_str());

    // safety checks against unknown udp replies on the same socket
    if (recvpkt.header.id != pkt.header.id) return MainDNSError.UnknownReplyId;
    if (!recvpkt.header.qr_flag) return MainDNSError.GotQuestion;

    // TODO: nicer error handling, with a nice print n stuff
    switch (@intToEnum(DNSPacketRCode, recvpkt.header.rcode)) {
        DNSPacketRCode.NoError => {
            try printPacket(recvpkt);
            return true;
        },
        DNSPacketRCode.ServFail => {
            // if SERVFAIL, the resolver should push to the next one.
            return false;
        },
        DNSPacketRCode.NotImpl, DNSPacketRCode.Refused, DNSPacketRCode.FmtError, DNSPacketRCode.NameErr => {
            var val = @intToEnum(DNSPacketRCode, recvpkt.header.rcode);
            std.debug.warn("{}\n", val);
            return MainDNSError.RCodeErr;
        },
        else => unreachable,
    }
}

fn makeDNSPacket(
    allocator: *std.mem.Allocator,
    name: []u8,
    qtype: []u8,
) !DNSPacket {
    var qtype_i = try types.strToType(qtype);
    var pkt = try DNSPacket.init(allocator, ""[0..]);

    // set random u16 as the id + all the other goodies in the header
    var r = std.rand.DefaultPrng.init(std.os.time.timestamp());
    const random_id = r.random.int(u16);
    pkt.header.id = random_id;
    pkt.header.rd = true;

    var question = packet.DNSQuestion{
        .qname = try packet.toDNSName(allocator, name),
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

    std.debug.warn("sending packet: {}\n", pkt.as_str());

    // read /etc/resolv.conf for nameserver
    var nameservers = try resolv.readNameservers();

    for (nameservers) |nameserver| {
        if (nameserver[0] == 0) continue;

        // TODO: ipv6 address support
        //var ip4addr = try std.net.parseIp4("127.0.0.1");
        //var addr = std.net.Address.initIp4(ip4addr, 36953);
        var ip4addr = try std.net.parseIp4(nameserver);
        var addr = std.net.Address.initIp4(ip4addr, 53);

        if (try resolve(allocator, addr, pkt)) break;
    }
}
