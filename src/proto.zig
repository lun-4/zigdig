// DNS protocol helpers, e.g starting a socket.
const std = @import("std");
const net = std.net;
const os = std.os;
const io = std.io;

const Allocator = std.mem.Allocator;

const packet = @import("packet.zig");
const resolv = @import("resolvconf.zig");
const main = @import("main.zig");
const rdata = @import("rdata.zig");

const DNSPacket = packet.DNSPacket;
const DNSPacketRCode = packet.DNSPacketRCode;
const DNSHeader = packet.DNSHeader;

const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;

/// Returns the socket file descriptor for an UDP socket.
pub fn openDNSSocket() !i32 {
    var flags: u32 = os.SOCK_DGRAM;
    if (std.event.Loop.instance) |_| {
        flags |= os.SOCK_NONBLOCK;
    }

    return try os.socket(
        os.AF_INET,
        flags,
        os.PROTO_udp,
    );
}

pub fn sendDNSPacket(sockfd: i32, addr: *const std.net.Address, pkt: DNSPacket, buffer: []u8) !void {
    var out = io.SliceOutStream.init(buffer);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);

    try serializer.serialize(pkt);
    try serializer.flush();

    _ = try std.os.sendto(sockfd, buffer, 0, &addr.os_addr, @sizeOf(std.os.sockaddr));
}

fn base64Encode(data: []u8) void {
    var b64_buf: [0x100000]u8 = undefined;
    var encoded = b64_buf[0..std.base64.Base64Encoder.calcSize(data.len)];
    std.base64.standard_encoder.encode(encoded, data);
    std.debug.warn("b64 encoded: '{}'\n", encoded);
}

pub fn recvDNSPacket(sockfd: os.fd_t, allocator: *Allocator) !DNSPacket {
    var buffer = try allocator.alloc(u8, 1024);
    var byte_count = try os.read(sockfd, buffer);

    var packet_slice = buffer[0..byte_count];
    var pkt = DNSPacket.init(allocator, packet_slice);

    var in = io.SliceInStream.init(packet_slice);
    var in_stream = &in.stream;
    var deserializer = packet.DNSDeserializer.init(in_stream);

    try deserializer.deserializeInto(&pkt);
    return pkt;
}

pub const AddressArrayList = std.ArrayList(std.net.Address);

pub const AddressList = struct {
    addrs: AddressArrayList,
    canon_name: ?[]u8,

    pub fn deinit(self: *@This()) void {
        self.addrs.deinit();
    }
};

fn toSlicePollFd(allocator: *std.mem.Allocator, fds: []os.fd_t) ![]os.pollfd {
    var pollfds = try allocator.alloc(os.pollfd, fds.len);
    for (fds) |fd, idx| {
        pollfds[idx] = os.pollfd{ .fd = fd, .events = os.POLLIN, .revents = 0 };
    }

    return pollfds;
}

pub fn getAddressList(allocator: *std.mem.Allocator, name: []const u8, port: u16) !*AddressList {
    var result = try allocator.create(AddressList);
    result.* = AddressList{
        .addrs = AddressArrayList.init(allocator),
        .canon_name = null,
    };

    var fd = try openDNSSocket();

    var nameservers = try resolv.readNameservers(allocator);
    var addrs = std.ArrayList(std.net.Address).init(allocator);
    defer addrs.deinit();

    for (nameservers.toSlice()) |nameserver| {
        var ns_addr = blk: {
            var addr: std.net.Address = undefined;
            var is_ipv4 = false;

            var ip4addr = std.net.parseIp4(nameserver) catch |err| {
                var ip6addr = try std.net.parseIp6(nameserver);
                addr = std.net.Address.initIp6(ip6addr, 53);
                break :blk addr;
            };

            addr = std.net.Address.initIp4(ip4addr, 53);
            break :blk addr;
        };

        try addrs.append(ns_addr);
    }

    var packet_a = try main.makeDNSPacket(allocator, name, "A");
    var packet_aaaa = try main.makeDNSPacket(allocator, name, "AAAA");

    var buf_a = try allocator.alloc(u8, packet_a.size());
    var buf_aaaa = try allocator.alloc(u8, packet_aaaa.size());

    for (addrs.toSlice()) |addr| {
        try sendDNSPacket(fd, &addr, packet_a, buf_a);
        try sendDNSPacket(fd, &addr, packet_aaaa, buf_aaaa);
    }

    var fds = [_]os.fd_t{fd};
    var pollfds = try toSlicePollFd(allocator, fds[0..]);
    const sockets = try os.poll(pollfds, 300);
    if (sockets == 0) return error.TimedOut;

    // TODO wrap this in a while true so we can retry servers who fail

    for (pollfds) |incoming| {
        if (incoming.revents == 0) continue;
        if (incoming.revents != os.POLLIN) return error.UnexpectedPollFd;

        std.debug.warn("fd {} is available\n", incoming.fd);
        var pkt = try recvDNSPacket(incoming.fd, allocator);
        if (!pkt.header.qr_flag) return error.GotQuestion;

        // TODO remove fd from poll() and try again when no answer
        if (pkt.header.ancount == 0) return error.NoAnswers;

        // TODO check pkt.header.rcode
        var ans = pkt.answers.at(0);
        // try main.printPacket(pkt);
        result.canon_name = try ans.name.toStr(allocator);
        var pkt_rdata = try rdata.parseRData(pkt, ans, ans.rdata);
        var addr = switch (pkt_rdata) {
            .A => |addr| blk: {
                break :blk std.net.Address.initIp4(addr.os_addr.in.addr, port);
            },
            .AAAA => |addr| blk: {
                var ip6 = std.net.Ip6Addr{ .scope_id = 0, .addr = addr.os_addr.in6.addr };
                break :blk std.net.Address.initIp6(ip6, port);
            },
            else => unreachable,
        };

        try result.addrs.append(addr);
        return result;
    }

    return result;
}
