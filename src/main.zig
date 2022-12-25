const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.zigdig_main);

pub fn main() !void {
    //var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer {
    //    _ = gpa.deinit();
    //}
    //const allocator = gpa.allocator();

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

    // create our packet
    const packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &[_]dns.Question{
            .{
                .name = name,
                .typ = qtype,
                .class = .IN,
            },
        },
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    logger.debug("packet: {}", .{packet});

    const conn = try dns.helpers.connectToSystemResolver();
    defer conn.close();

    logger.info("selected nameserver: {}\n", .{conn.address});

    try conn.sendPacket(packet);

    //const reply_packet = try conn.receivePacket(allocator, 4092);
    //defer reply_packet.deinit();
    //logger.info("reply: {}", .{reply_packet});

    //try std.testing.expectEqual(reply_packet.header.id == packet.header.id);
    //try std.testing.expect(reply_packet.header.is_response);

    const stdout = std.io.getStdOut();

    try dns.helpers.printAsZoneFile(packet, stdout.writer());
    //try dns.helpers.printAsZoneFile(reply_packet, stdout.writer());
}

test "awooga" {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("test.zig"));
}
