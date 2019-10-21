// DNS protocol helpers, e.g starting a socket.
const std = @import("std");
const net = std.net;
const os = std.os;
const io = std.io;

const Allocator = std.mem.Allocator;

const packet = @import("packet.zig");
const DNSPacket = packet.DNSPacket;
const DNSHeader = packet.DNSHeader;

const DNSError = error{NetError};
const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;

/// Returns the socket file descriptor for an UDP socket.
pub fn openDNSSocket(addr: *net.Address) !i32 {
    var sockfd = try os.socket(
        os.AF_INET,
        os.SOCK_DGRAM,
        os.PROTO_udp,
    );

    try os.connect(sockfd, &addr.os_addr, @sizeOf(os.sockaddr));
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

pub fn recvDNSPacket(sockfd: i32, allocator: *Allocator) !DNSPacket {
    var buffer = try allocator.alloc(u8, 512);
    var byte_count = try os.read(sockfd, buffer);
    if (byte_count == 0) return DNSError.NetError;

    var packet_slice = buffer[0..byte_count];
    var pkt = DNSPacket.init(allocator, packet_slice);

    //std.debug.warn("recv {} bytes for packet\n", byte_count);
    //base64Encode(packet_slice);

    var in = io.SliceInStream.init(packet_slice);
    var in_stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);

    try deserializer.deserializeInto(&pkt);
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
    var addr = std.net.Address.initIp6(&ip6addr, 53);

    // TODO fails on linux
    //var sockfd = try openDNSSocket(&addr);
    //defer os.close(sockfd);
}
