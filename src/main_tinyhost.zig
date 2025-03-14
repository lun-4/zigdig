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
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= @intFromEnum(@import("root").current_log_level)) {
        std.log.defaultLog(message_level, scope, format, args);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = gpa.deinit();
    }
    const allocator = gpa.allocator();

    const debug = std.process.getEnvVarOwned(allocator, "DEBUG") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer allocator.free(debug);
    if (std.mem.eql(u8, debug, "1")) current_log_level = .debug;

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();
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
