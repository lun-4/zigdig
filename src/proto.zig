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

const DNSError = error{NetError};
const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;

/// Returns the socket file descriptor for an UDP socket.
pub fn openDNSSocket(addr: *net.Address) !i32 {
    var flags: u32 = os.SOCK_DGRAM;
    if (std.event.Loop.instance) |_| {
        flags |= os.SOCK_NONBLOCK;
    }

    var sockfd = try os.socket(
        os.AF_INET,
        flags,
        os.PROTO_udp,
    );

    if (std.event.Loop.instance) |_| {
        try os.connect_async(sockfd, &addr.os_addr, @sizeOf(os.sockaddr));
    } else {
        try os.connect(sockfd, &addr.os_addr, @sizeOf(os.sockaddr));
    }
    return sockfd;
}

pub fn sendDNSPacket(sockfd: i32, pkt: DNSPacket, buffer: []u8) !void {
    var out = io.SliceOutStream.init(buffer);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);

    try serializer.serialize(pkt);
    try serializer.flush();

    try os.write(sockfd, buffer);
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
    if (byte_count == 0) return DNSError.NetError;

    var packet_slice = buffer[0..byte_count];
    var pkt = DNSPacket.init(allocator, packet_slice);

    var in = io.SliceInStream.init(packet_slice);
    var in_stream = &in.stream;
    var deserializer = packet.DNSDeserializer.init(in_stream);

    //try deserializer.deserializeInto(&pkt);
    return pkt;
}

test "fake socket open/close" {
    var ip4addr = try std.net.parseIp4("127.0.0.1");
    var addr = std.net.Address.initIp4(ip4addr, 53);
    var sockfd = try openDNSSocket(&addr);
    defer os.close(sockfd);
}

test "fake socket open/close (ip6)" {
    var ip6addr = try std.net.parseIp6("0:0:0:0:0:0:0:1");
    var addr = std.net.Address.initIp6(ip6addr, 53);

    //var sockfd = try openDNSSocket(&addr);
    //defer os.close(sockfd);
}

pub const AddressArrayList = std.ArrayList(std.net.Address);

pub const AddressList = struct {
    addrs: AddressArrayList,
    canon_name: ?[]u8,

    pub fn deinit(self: *@This()) void {
        self.addrs.deinit();
    }
};

pub const pollfd = extern struct {
    fd: os.fd_t,
    events: i16,
    revents: i16,
};

fn poll(fds: []pollfd, timeout: usize) usize {
    const rc = os.system.syscall3(os.system.SYS_poll, @ptrToInt(fds.ptr), fds.len, timeout);
    return rc;
}

const POLLIN = 0x001;

fn toSlicePollFd(allocator: *std.mem.Allocator, fds: []os.fd_t) ![]pollfd {
    var pollfds = try allocator.alloc(pollfd, fds.len);
    std.mem.secureZero(pollfd, pollfds);
    for (fds) |fd, idx| {
        pollfds[idx] = pollfd{ .fd = fd, .events = POLLIN, .revents = 0 };
    }

    return pollfds;
}

pub fn getAddressList(allocator: *std.mem.Allocator, name: []const u8, port: u16) !*AddressList {
    var result = try allocator.create(AddressList);
    result.* = AddressList{
        .addrs = AddressArrayList.init(allocator),
        .canon_name = null,
    };

    var nameservers = try resolv.readNameservers(allocator);
    var fds = std.ArrayList(os.fd_t).init(allocator);

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

        var fd = try openDNSSocket(&ns_addr);
        try fds.append(fd);
    }

    var packet_a = try main.makeDNSPacket(allocator, name, "A");
    var packet_aaaa = try main.makeDNSPacket(allocator, name, "AAAA");

    var buf_a = try allocator.alloc(u8, packet_a.size());
    var buf_aaaa = try allocator.alloc(u8, packet_aaaa.size());

    for (fds.toSlice()) |fd| {
        try sendDNSPacket(fd, packet_a, buf_a);
        try sendDNSPacket(fd, packet_aaaa, buf_aaaa);
    }

    var pollfds = try toSlicePollFd(allocator, fds.toSlice());
    const rc = poll(pollfds, 300);
    std.debug.warn("rc = {}\n", rc);
    const errno = os.system.getErrno(rc);
    if (errno < 0) return error.PollFail;
    if (rc == 0) return error.TimedOut;

    // TODO wrap this in a while true so we can retry servers who fail

    for (pollfds) |incoming| {
        if (incoming.revents == 0) continue;
        if (incoming.revents != POLLIN) return error.UnexpectedPollFd;
        std.debug.warn("fd {} is available\n", incoming.fd);
        var pkt = try recvDNSPacket(incoming.fd, allocator);
        if (!pkt.header.qr_flag) return error.GotQuestion;

        // TODO remove fd from poll() and try again
        if (pkt.header.ancount == 0) return error.NoAnswers;

        // TODO check pkt.header.rcode
        var ans = pkt.answers.at(0);
        //try main.printPacket(pkt);
        result.canon_name = try ans.name.toStr(allocator);
        var pkt_rdata = try rdata.parseRData(pkt, ans, ans.rdata);
        var addr = switch (pkt_rdata) {
            .A => |addr| addr,
            .AAAA => |addr| addr,
            else => unreachable,
        };
        try result.addrs.append(addr);
        return result;
    }

    return result;
}
