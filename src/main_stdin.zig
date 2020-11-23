const std = @import("std");
const os = std.os;
const fmt = std.fmt;
const io = std.io;

const dns = @import("dns");
const rdata = dns.rdata;

pub const DNSPacket = dns.Packet;
pub const DNSPacketRCode = dns.ResponseCode;
pub const DNSClass = dns.DNSClass;
const Allocator = std.mem.Allocator;
const mainlib = @import("main.zig");

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
fn printList(pkt: DNSPacket, resource_list: dns.ResourceList) !void {
    // TODO the formatting here is not good...
    std.debug.warn(";;name\t\t\trrtype\tclass\tttl\trdata\n");

    for (resource_list.items) |resource| {
        var pkt_rdata = try rdata.parseRData(pkt, resource, resource.opaque_rdata);

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

        for (pkt.questions.items) |question| {
            std.debug.warn(
                ";{}.\t{}\t{}\n",
                try question.qname.toStr(pkt.allocator),
                @tagName(question.qtype),
                @tagName(question.qclass),
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
    std.debug.warn("recv packet: {}\n", recvpkt.header.repr());

    // safety checks against unknown udp replies on the same socket
    if (recvpkt.header.id != pkt.header.id) return MainDNSError.UnknownReplyId;
    if (!recvpkt.header.qr_flag) return MainDNSError.GotQuestion;

    switch (recvpkt.header.rcode) {
        .NoError => {
            try printPacket(recvpkt);
            return true;
        },
        .ServFail => {
            // if SERVFAIL, the resolver should push to the next one.
            return false;
        },
        .NotImpl, .Refused, .FmtError, .NameErr => {
            std.debug.warn("response code: {}\n", recvpkt.header.rcode);
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
    qtype_str: []const u8,
) !DNSPacket {
    var qtype = try dns.DNSType.fromStr(qtype_str);
    var pkt = DNSPacket.init(allocator, ""[0..]);

    // set random u16 as the id + all the other goodies in the header
    var r = std.rand.DefaultPrng.init(std.time.timestamp());
    const random_id = r.random.int(u16);
    pkt.header.id = random_id;
    pkt.header.rd = true;

    var question = dns.Question{
        .qname = try dns.DNSName.fromString(allocator, name),
        .qtype = qtype,
        .qclass = DNSClass.IN,
    };

    try pkt.addQuestion(question);

    return pkt;
}

pub fn main() anyerror!void {
    var allocator_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = allocator_instance.deinit();
    }
    const allocator = &allocator_instance.allocator;

    var stdin = std.io.getStdIn();

    var buffer = try allocator.alloc(u8, 1024);
    var byte_count = try stdin.reader().read(buffer);
    var packet_slice = buffer[0..byte_count];

    var pkt = DNSPacket.init(allocator, packet_slice);

    var in = dns.FixedStream{ .buffer = packet_slice, .pos = 0 };
    var deserializer = dns.DNSDeserializer.init(in.reader());

    try deserializer.deserializeInto(&pkt);
    try mainlib.printPacket(pkt);
}
