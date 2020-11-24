const std = @import("std");
const root = @import("./dns.zig");

/// Create a DNS request packet.
/// Receives the full DNS name to be resolved, "google.com" (without)
pub fn createRequestPacket(allocator: *std.mem.Allocator, name_string: []const u8, resource_type: root.ResourceType) !root.Packet {

    // TODO remove need to allocate here. how?
    const name = try root.Name.fromString(allocator, name_string);

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
    };
}

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn openSocketAnyResolver() !std.fs.File {}

/// Send a DNS packet to socket.
pub fn sendPacket(sock: std.fs.File, packet: root.Packet) !void {}

/// Receive a DNS packet from a socket.
pub fn recvPacket(sock: std.fs.File, read_buffer: []u8) !root.Packet {}
