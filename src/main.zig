const std = @import("std");

const packet = @import("packet.zig");

test "zigdig" {
    _ = @import("packet.zig");
}

pub fn main() anyerror!void {
    var pack = packet.DNSPacket.init();
    var buf: [1024]u8 = undefined;
    std.debug.warn("{}\n", pack.as_str());
}
