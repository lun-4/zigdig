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

    const conn = try dns.helpers.connectToSystemResolver();
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

test "awooga" {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("test.zig"));
    std.testing.refAllDecls(@import("name.zig"));
    std.testing.refAllDecls(@import("helpers.zig"));
    std.testing.refAllDecls(@import("cidr.zig"));
}
