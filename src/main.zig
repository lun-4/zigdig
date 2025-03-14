const std = @import("std");
const builtin = @import("builtin");
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

    if (builtin.os.tag == .windows) {
        const debug = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "DEBUG");
        defer allocator.free(debug);

        const debug_expected = try std.unicode.utf8ToUtf16LeAllocZ(allocator, "1");
        defer allocator.free(debug_expected);

        if (std.mem.eql(u16, std.process.getenvW(debug) orelse &[_]u16{0}, debug_expected)) current_log_level = .debug;
    } else {
        if (std.mem.eql(u8, std.posix.getenv("DEBUG") orelse "", "1")) current_log_level = .debug;
    }

    var args_it = try std.process.argsWithAllocator(allocator);
    defer args_it.deinit();
    _ = args_it.skip();

    const name_string = (args_it.next() orelse {
        logger.warn("no name provided", .{});
        return error.InvalidArgs;
    });

    const qtype_str = (args_it.next() orelse {
        logger.warn("no qtype provided", .{});
        return error.InvalidArgs;
    });

    const qtype = dns.ResourceType.fromString(qtype_str) catch |err| switch (err) {
        error.InvalidResourceType => {
            logger.warn("invalid query type provided", .{});
            return error.InvalidArgs;
        },
    };

    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(name_string, &name_buffer);

    var questions = [_]dns.Question{
        .{
            .name = name,
            .typ = qtype,
            .class = .IN,
        },
    };

    var empty = [0]dns.Resource{};

    // create question packet
    var packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &empty,
        .nameservers = &empty,
        .additionals = &empty,
    };

    logger.debug("packet: {}", .{packet});

    const conn = if (builtin.os.tag == .windows) try dns.helpers.connectToResolver("8.8.8.8", null) else try dns.helpers.connectToSystemResolver();
    defer conn.close();

    logger.info("selected nameserver: {}\n", .{conn.address});
    const stdout = std.io.getStdOut();

    // print out our same question as a zone file for debugging purposes
    try dns.helpers.printAsZoneFile(&packet, undefined, stdout.writer());

    try conn.sendPacket(packet);

    // as we need Names inside the NamePool to live beyond the call to
    // receiveFullPacket (since we need to deserialize names in RDATA)
    // we must take ownership of them and deinit ourselves
    var name_pool = dns.NamePool.init(allocator);
    defer name_pool.deinitWithNames();

    const reply = try conn.receiveFullPacket(
        allocator,
        4096,
        .{ .name_pool = &name_pool },
    );
    defer reply.deinit(.{ .names = false });

    const reply_packet = reply.packet;
    logger.debug("reply: {}", .{reply_packet});

    try std.testing.expectEqual(packet.header.id, reply_packet.header.id);
    try std.testing.expect(reply_packet.header.is_response);

    try dns.helpers.printAsZoneFile(reply_packet, &name_pool, stdout.writer());
}
