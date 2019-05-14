const std = @import("std");
const os = std.os;

const packet = @import("packet.zig");
const proto = @import("proto.zig");

test "zigdig" {
    _ = @import("packet.zig");
    _ = @import("proto.zig");
}

pub fn main() anyerror!void {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();

    const allocator = &arena.allocator;
    var args_it = os.args();

    _ = args_it.skip();

    const name = try (args_it.next(allocator) orelse {
        std.debug.warn("no name provided\n");
        return error.InvalidArgs;
    });

    const rr_type = try (args_it.next(allocator) orelse {
        std.debug.warn("no rr type provided\n");
        return error.InvalidArgs;
    });

    std.debug.warn("{} {}\n", name, rr_type);
}
