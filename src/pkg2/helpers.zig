const std = @import("std");
const root = @import("./dns.zig");

const resolvconf = @import("./resolvconf.zig");

/// Create a DNS request packet.
/// Receives the full DNS name to be resolved, "google.com" (without)
pub fn createRequestPacket(
    name: root.Name,
    resource_type: root.ResourceType,
) !root.Packet {
    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);

    return root.Packet{
        .header = .{
            .id = r.random.int(u16),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &[_]root.Question{
            root.Question{
                .name = name,
                .typ = resource_type,
                .class = .IN,
            },
        },
        .answers = &[_]root.Resource{},
        .nameservers = &[_]root.Resource{},
        .additionals = &[_]root.Resource{},
    };
}

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn openSocketAnyResolver() !std.net.StreamServer.Connection {
    var out_buffer: [256]u8 = undefined;
    const nameserver_address_string = (try resolvconf.randomNameserver(&out_buffer)).?;

    var addr = try std.net.Address.resolveIp(nameserver_address_string, 53);

    var flags: u32 = std.os.SOCK_DGRAM;
    const fd = try std.os.socket(std.os.AF_INET, flags, std.os.IPPROTO_UDP);

    return std.net.StreamServer.Connection{
        .address = addr,
        .file = std.fs.File{ .handle = fd },
    };
}

/// Send a DNS packet to socket.
pub fn sendPacket(conn: std.net.StreamServer.Connection, packet: root.Packet) !void {
    std.debug.warn("{}\n", .{packet});
    std.debug.warn("name: {}\n", .{packet.questions[0].name.labels.ptr});
    std.debug.warn("name: {}\n", .{packet.questions[0].name.labels.len});
    std.debug.warn("{}\n", .{packet.questions[0]});

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
    _ = try std.os.sendto(conn.file.handle, result, 0, &conn.address.any, @sizeOf(std.os.sockaddr));
}

/// Receive a DNS packet from a socket.
pub fn recvPacket(sock: std.fs.File, read_buffer: []u8) !root.Packet {}
