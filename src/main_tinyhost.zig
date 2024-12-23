const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);
pub const std_options = std.Options{
    .log_level = .debug,
    .logFn = logfn,
};

pub var current_log_level: std.log.Level = .info;

fn logfn(
    comptime message_level: std.log.Level,
    comptime scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= @intFromEnum(@import("root").current_log_level)) {
        std.log.defaultLog(message_level, scope, format, args);
    }
}

pub fn main() !void {
    if (std.mem.eql(u8, std.posix.getenv("DEBUG") orelse "", "1")) current_log_level = .debug;
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

    var addrs = try dns.helpers.getAddressList(name_string, 80, allocator);
    defer addrs.deinit();

    var stdout = std.io.getStdOut().writer();

    for (addrs.addrs) |addr| {
        try stdout.print("{s} has address {any}\n", .{ name_string, addr });
    }
}
