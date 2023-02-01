const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = gpa.deinit();
    }
    const allocator = gpa.allocator();

    var args_it = std.process.args();
    _ = args_it.skip();

    const name_string = (args_it.next() orelse {
        logger.warn("no name provided", .{});
        return error.InvalidArgs;
    });

    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(name_string, &name_buffer);

    var addrs = try dns.helpers.getAddressList(name, allocator);
    defer allocator.free(addrs);

    var stdout = std.io.getStdOut().writer();

    for (addrs) |addr| {
        try stdout.print("{} has address {}\n", .{addr});
    }
}
