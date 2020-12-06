const std = @import("std");
const root = @import("./dns.zig");
const dns = root;

const resolvconf = @import("./resolvconf.zig");

pub fn randomId() u16 {
    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);
    return r.random.int(u16);
}

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn openSocketAnyResolver() !std.net.StreamServer.Connection {
    var out_buffer: [256]u8 = undefined;
    const nameserver_address_string = (try resolvconf.randomNameserver(&out_buffer)).?;

    var addr = try std.net.Address.resolveIp(nameserver_address_string, 53);

    var flags: u32 = std.os.SOCK_DGRAM;
    const fd = try std.os.socket(addr.any.family, flags, std.os.IPPROTO_UDP);

    return std.net.StreamServer.Connection{
        .address = addr,
        .file = std.fs.File{ .handle = fd },
    };
}

/// Send a DNS packet to socket.
pub fn sendPacket(conn: std.net.StreamServer.Connection, packet: root.Packet) !void {
    // we hold this buffer because File won't use sendto()
    // and we need sendto() for UDP sockets. (makes sense)
    //
    // this is a limitation of std.net.
    var buffer: [1024]u8 = undefined;

    const typ = std.io.FixedBufferStream([]u8);
    var stream = typ{ .buffer = &buffer, .pos = 0 };
    var serializer = std.io.Serializer(.Big, .Bit, typ.Writer).init(stream.writer());

    try serializer.serialize(packet);
    try serializer.flush();

    var result = buffer[0..packet.size()];
    const dest_len: u32 = switch (conn.address.any.family) {
        std.os.AF_INET => @sizeOf(std.os.sockaddr_in),
        std.os.AF_INET6 => @sizeOf(std.os.sockaddr_in6),
        else => unreachable,
    };

    _ = try std.os.sendto(conn.file.handle, result, 0, &conn.address.any, dest_len);
}

/// Receive a DNS packet from a socket.
pub fn recvPacket(conn: std.net.StreamServer.Connection, ctx: *dns.DeserializationContext) !root.Packet {
    var packet_buffer: [1024]u8 = undefined;
    const read_bytes = try conn.file.read(&packet_buffer);

    const packet_bytes = packet_buffer[0..read_bytes];

    var pkt = dns.Packet{
        .header = .{},
        .questions = &[_]dns.Question{},
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    var stream = std.io.FixedBufferStream([]const u8){ .buffer = packet_bytes, .pos = 0 };
    try pkt.readInto(stream.reader(), ctx);

    return pkt;
}
