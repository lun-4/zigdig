const std = @import("std");
const os = std.os;
const fmt = std.fmt;

pub const proto = @import("proto.zig");
pub const resolv = @import("resolvconf.zig");

const dns = @import("dns");
const rdata = dns.rdata;

pub const DNSPacket = dns.Packet;
pub const DNSPacketRCode = dns.ResponseCode;
pub const DNSClass = dns.Class;
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
fn printList(allocator: *std.mem.Allocator, pkt: dns.Packet, resource_list: []dns.Resource) !void {
    // TODO the formatting here is not good...
    std.debug.warn(";;name\t\t\trrtype\tclass\tttl\trdata\n", .{});

    for (resource_list) |resource| {
        var resource_data = try dns.ResourceData.fromOpaque(allocator, resource.typ, resource.opaque_rdata);

        std.debug.warn("{}.\t{}\t{}\t{}\t{}\n", .{
            resource.name,
            @tagName(resource.typ),
            @tagName(resource.class),
            resource.ttl,
            resource_data,
        });
    }

    std.debug.warn("\n", .{});
}

/// Print a packet to stderr.
pub fn printPacket(allocator: *std.mem.Allocator, pkt: dns.Packet) !void {
    std.debug.warn("id: {}, opcode: {}, rcode: {}\n", .{
        pkt.header.id,
        pkt.header.opcode,
        pkt.header.response_code,
    });

    std.debug.warn("qd: {}, an: {}, ns: {}, ar: {}\n\n", .{
        pkt.header.question_length,
        pkt.header.answer_length,
        pkt.header.nameserver_length,
        pkt.header.additional_length,
    });

    if (pkt.header.question_length > 0) {
        std.debug.warn(";;-- question --\n", .{});
        std.debug.warn(";;name\ttype\tclass\n", .{});

        for (pkt.questions) |question| {
            std.debug.warn(";{}.\t{}\t{}\n", .{
                question.name,
                @tagName(question.typ),
                @tagName(question.class),
            });
        }

        std.debug.warn("\n", .{});
    }

    if (pkt.header.answer_length > 0) {
        std.debug.warn(";; -- answer --\n", .{});
        try printList(allocator, pkt, pkt.answers);
    } else {
        std.debug.warn(";; no answer\n", .{});
    }

    if (pkt.header.nameserver_length > 0) {
        std.debug.warn(";; -- authority --\n", .{});
        try printList(allocator, pkt, pkt.nameservers);
    } else {
        std.debug.warn(";; no authority\n\n", .{});
    }

    if (pkt.header.additional_length > 0) {
        std.debug.warn(";; -- additional --\n", .{});
        try printList(allocator, pkt, pkt.additionals);
    } else {
        std.debug.warn(";; no additional\n\n", .{});
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
    defer recvpkt.deinit();
    std.debug.warn("recv packet: {}\n", .{recvpkt.header});

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
            std.debug.warn("response code: {}\n", .{recvpkt.header.rcode});
            return MainDNSError.RCodeErr;
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
    var qtype = try dns.Type.fromStr(qtype_str);
    var pkt = DNSPacket.init(allocator, ""[0..]);

    // set random u16 as the id + all the other goodies in the header
    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);

    const random_id = r.random.int(u16);
    pkt.header.id = random_id;
    pkt.header.rd = true;

    var question = dns.Question{
        .qname = try dns.Name.fromString(allocator, name),
        .qtype = qtype,
        .qclass = DNSClass.IN,
    };

    try pkt.addQuestion(question);

    return pkt;
}

pub fn oldMain() anyerror!void {
    var allocator_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = allocator_instance.deinit();
    }
    const allocator = &allocator_instance.allocator;

    var args_it = std.process.args();

    _ = args_it.skip();

    const name = (args_it.nextPosix() orelse {
        std.debug.warn("no name provided\n", .{});
        return error.InvalidArgs;
    });

    const qtype = (args_it.nextPosix() orelse {
        std.debug.warn("no qtype provided\n", .{});
        return error.InvalidArgs;
    });

    var pkt = try makeDNSPacket(allocator, name, qtype);
    std.debug.warn("sending packet: {}\n", .{pkt.header});

    // read /etc/resolv.conf for nameserver
    var nameservers = try resolv.readNameservers(allocator);
    defer resolv.freeNameservers(allocator, nameservers);

    for (nameservers.items) |nameserver| {
        if (nameserver[0] == 0) continue;

        // we don't know if the given nameserver address is ip4 or ip6, so we
        // try parsing it as ip4, then ip6.
        var ns_addr = try std.net.Address.parseIp(nameserver, 53);
        if (try resolve(allocator, &ns_addr, pkt)) break;
    }
}

pub fn main() !void {
    var allocator_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = allocator_instance.deinit();
    }
    const allocator = &allocator_instance.allocator;

    var args_it = std.process.args();

    _ = args_it.skip();

    const name_string = (args_it.nextPosix() orelse {
        std.debug.warn("no name provided\n", .{});
        return error.InvalidArgs;
    });

    const qtype_str = (args_it.nextPosix() orelse {
        std.debug.warn("no qtype provided\n", .{});
        return error.InvalidArgs;
    });

    const qtype = dns.ResourceType.fromString(qtype_str) catch |err| switch (err) {
        error.InvalidResourceType => {
            std.debug.warn("invalid query type provided\n", .{});
            return error.InvalidArgs;
        },
    };

    var name_buffer: [32][]const u8 = undefined;
    const name = try dns.Name.fromString(name_string, &name_buffer);

    const packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &[_]dns.Question{
            .{
                .name = name,
                .typ = qtype,
                .class = .IN,
            },
        },
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    std.debug.warn("{}\n", .{packet});

    const conn = try dns.helpers.openSocketAnyResolver();
    defer conn.file.close();

    std.debug.warn("selected nameserver: {}\n", .{conn.address});

    try dns.helpers.sendPacket(conn, packet);

    var work_memory: [0x100000]u8 = undefined;
    const reply = try dns.helpers.recvPacket(conn, &work_memory);

    std.debug.warn("reply!!!: {}\n", .{reply});

    std.debug.assert(reply.header.id == packet.header.id);
    std.debug.assert(reply.header.is_response);

    switch (reply.header.response_code) {
        .NoError => try printPacket(allocator, reply),
        .ServFail => std.debug.warn("shit, got SERVFAIL\n", .{}),
        .NotImplemented, .Refused, .FormatError, .NameError => @panic("unexpected response code"),
    }
}
