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
const DNSClass = types.DNSClass;
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

/// Print a slice of DNSResource to stderr.
fn printList(pkt: packet.DNSPacket, resource_list: packet.ResourceList) !void {
    // TODO the formatting here is not good...
    std.debug.warn(";;name\t\t\trrtype\tclass\tttl\trdata\n");

    for (resource_list.toSlice()) |resource| {
        var pkt_rdata = try rdata.parseRData(pkt, resource, resource.rdata);

        std.debug.warn(
            "{}.\t{}\t{}\t{}\t{}\n",
            try resource.name.toStr(pkt.allocator),
            @tagName(resource.rr_type),
            @tagName(resource.class),
            resource.ttl,
            try rdata.prettyRData(pkt.allocator, pkt_rdata),
        );
    }

    std.debug.warn("\n");
}

/// Print a packet to stderr.
pub fn printPacket(pkt: DNSPacket) !void {
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
        std.debug.warn(";;qname\tqtype\tqclass\n");

        for (pkt.questions.toSlice()) |question| {
            std.debug.warn(
                ";{}.\t{}\t{}\n",
                try question.qname.toStr(pkt.allocator),
                @tagName(question.qtype),
                types.classToStr(question.qclass),
            );
        }

        std.debug.warn("\n");
    }

    if (pkt.header.ancount > 0) {
        std.debug.warn(";; -- answer --\n");
        try printList(pkt, pkt.answers);
    } else {
        std.debug.warn(";; no answer\n");
    }

    if (pkt.header.nscount > 0) {
        std.debug.warn(";; -- authority --\n");
        try printList(pkt, pkt.authority);
    } else {
        std.debug.warn(";; no authority\n\n");
    }

    if (pkt.header.ancount > 0) {
        std.debug.warn(";; -- additional --\n");
        try printList(pkt, pkt.additional);
    } else {
        std.debug.warn(";; no additional\n\n");
    }
}

/// Sends pkt over a given socket directed by `addr`, returns a boolean
/// if this was successful or not. A value of false should direct clients
/// to follow the next nameserver in the list.
fn resolve(allocator: *Allocator, addr: *std.net.Address, pkt: DNSPacket) !bool {
    // TODO this fails on linux when addr is an ip6 addr...
    var sockfd = try proto.openDNSSocket();
    errdefer std.os.close(sockfd);

    var buf = try allocator.alloc(u8, pkt.size());
    try proto.sendDNSPacket(sockfd, addr, pkt, buf);

    var recvpkt = try proto.recvDNSPacket(sockfd, allocator);
    std.debug.warn("recv packet: {}\n", recvpkt.header.as_str());

    // safety checks against unknown udp replies on the same socket
    if (recvpkt.header.id != pkt.header.id) return MainDNSError.UnknownReplyId;
    if (!recvpkt.header.qr_flag) return MainDNSError.GotQuestion;

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

        else => {
            std.debug.warn("unhandled rcode: {}\n", recvpkt.header.rcode);
            return false;
        },
    }
}

/// Make a DNSPacket containing a single question out of the question's
/// QNAME and QTYPE. Both are strings and so are converted to the respective
/// DNSName and DNSType enum values internally.
/// Sets a random packet ID.
pub fn makeDNSPacket(
    allocator: *std.mem.Allocator,
    name: []const u8,
    qtype: []const u8,
) !DNSPacket {
    var qtype_i = try types.strToType(qtype);
    var pkt = DNSPacket.init(allocator, ""[0..]);

    // set random u16 as the id + all the other goodies in the header
    var r = std.rand.DefaultPrng.init(std.time.timestamp());
    const random_id = r.random.int(u16);
    pkt.header.id = random_id;
    pkt.header.rd = true;

    var question = packet.DNSQuestion{
        .qname = try packet.toDNSName(allocator, name),
        .qtype = @intToEnum(types.DNSType, qtype_i),
        .qclass = DNSClass.IN,
    };

    try pkt.addQuestion(question);

    return pkt;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    errdefer arena.deinit();

    const allocator = &arena.allocator;
    var args_it = std.process.args();

    _ = args_it.skip();

    const name = try (args_it.next(allocator) orelse {
        std.debug.warn("no name provided\n");
        return error.InvalidArgs;
    });

    const qtype = try (args_it.next(allocator) orelse {
        std.debug.warn("no qtype provided\n");
        return error.InvalidArgs;
    });

    var pkt = try makeDNSPacket(allocator, name, qtype);
    std.debug.warn("sending packet: {}\n", pkt.header.as_str());

    // read /etc/resolv.conf for nameserver
    var nameservers = try resolv.readNameservers(allocator);

    for (nameservers.toSlice()) |nameserver| {
        if (nameserver[0] == 0) continue;

        // we don't know if the given nameserver address is ip4 or ip6, so we
        // try parsing it as ip4, then ip6.
        var ns_addr = try proto.parseIncomingAddr(nameserver);
        if (try resolve(allocator, &ns_addr, pkt)) break;
    }
}
