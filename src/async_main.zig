const std = @import("std");
const os = std.os;
const proto = @import("proto.zig");

pub const io_mode = .evented;

pub fn main() anyerror!void {
    if (io_mode == .evented) {
        std.debug.warn("awo\n");
        const loop = std.event.Loop.instance.?;
        try loop.init();
        defer loop.deinit();

        var result: @typeOf(asyncMain).ReturnType.ErrorSet!void = undefined;
        var frame: @Frame(asyncMain) = undefined;
        _ = @asyncCall(&frame, &result, asyncMain, loop);
        loop.run();
        return result;
    } else {
        return allMain();
    }
}

async fn asyncMain(loop: *std.event.Loop) !void {
    loop.beginOneEvent();
    defer loop.finishOneEvent();

    return allMain();
}

pub fn allMain() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();

    const info = try proto.getAddressList(&arena.allocator, "ziglang.org", 443);
    defer info.deinit();

    if (info.canon_name) |canon| {
        std.debug.warn("canon name: {}\n", canon);
    }
    for (info.addrs.toSlice()) |addr| {
        std.debug.warn("found addr: {}\n", addr);
    }
}
