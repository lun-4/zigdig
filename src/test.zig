const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const io = std.io;

const dns = @import("lib.zig");
const Packet = dns.Packet;

test "convert domain string to dns name" {
    const domain = "www.google.com";
    var name_buffer: [3][]const u8 = undefined;
    const name = (try dns.Name.fromString(domain[0..], &name_buffer)).full;
    std.debug.assert(name.labels.len == 3);
    try std.testing.expect(std.mem.eql(u8, name.labels[0], "www"));
    try std.testing.expect(std.mem.eql(u8, name.labels[1], "google"));
    try std.testing.expect(std.mem.eql(u8, name.labels[2], "com"));
}

test "convert domain string to dns name (buffer overflow case)" {
    const domain = "www.google.com";
    var name_buffer: [1][]const u8 = undefined;
    _ = dns.Name.fromString(domain[0..], &name_buffer) catch |err| switch (err) {
        error.Overflow => {},
        else => return err,
    };
}

// extracted with 'dig google.com a +noedns'
const TEST_PKT_QUERY = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";
const TEST_PKT_RESPONSE = "RM2BgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASwABNg6yo4=";
const GOOGLE_COM_LABELS = [_][]const u8{ "google"[0..], "com"[0..] };

test "Packet serialize/deserialize" {
    const random_id = dns.helpers.randomHeaderId();
    const packet = dns.Packet{
        .header = .{ .id = random_id },
        .questions = &[_]dns.Question{},
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    var write_buffer: [1024]u8 = undefined;
    const buf = try serialTest(packet, &write_buffer);

    // deserialize it and compare if everythings' equal
    var incoming = try deserialTest(buf);
    defer incoming.deinit(.{});
    const deserialized = incoming.packet;

    try std.testing.expectEqual(deserialized.header.id, packet.header.id);

    const fields = [_][]const u8{ "id", "opcode", "question_length", "answer_length" };

    const new_header = deserialized.header;
    const header = packet.header;

    inline for (fields) |field| {
        try std.testing.expectEqual(
            @field(new_header, field),
            @field(header, field),
        );
    }
}

fn decodeBase64(encoded: []const u8, write_buffer: []u8) ![]const u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    try std.base64.standard.Decoder.decode(write_buffer[0..size], encoded);
    return write_buffer[0..size];
}

fn expectGoogleLabels(actual: [][]const u8) !void {
    for (actual, 0..) |label, idx| {
        try std.testing.expectEqualSlices(u8, label, GOOGLE_COM_LABELS[idx]);
    }
}

test "deserialization of original question google.com/A" {
    var write_buffer: [0x10000]u8 = undefined;

    const decoded = try decodeBase64(TEST_PKT_QUERY, &write_buffer);

    var incoming = try deserialTest(decoded);
    defer incoming.deinit(.{});
    const pkt = incoming.packet;

    try std.testing.expectEqual(@as(u16, 5189), pkt.header.id);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.question_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.answer_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.nameserver_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.additional_length);
    try std.testing.expectEqual(@as(usize, 1), pkt.questions.len);

    const question = pkt.questions[0];

    try expectGoogleLabels(question.name.?.full.labels);
    try std.testing.expectEqual(@as(usize, 12), question.name.?.full.packet_index.?);
    try std.testing.expectEqual(question.typ, dns.ResourceType.A);
    try std.testing.expectEqual(question.class, dns.ResourceClass.IN);
}

test "deserialization of reply google.com/A" {
    var encode_buffer: [0x10000]u8 = undefined;
    const decoded = try decodeBase64(TEST_PKT_RESPONSE, &encode_buffer);

    var incoming = try deserialTest(decoded);
    defer incoming.deinit(.{});
    const pkt = incoming.packet;

    try std.testing.expectEqual(@as(u16, 17613), pkt.header.id);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.question_length);
    try std.testing.expectEqual(@as(u16, 1), pkt.header.answer_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.nameserver_length);
    try std.testing.expectEqual(@as(u16, 0), pkt.header.additional_length);

    const question = pkt.questions[0];

    try expectGoogleLabels(question.name.?.full.labels);
    try testing.expectEqual(dns.ResourceType.A, question.typ);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);

    const answer = pkt.answers[0];

    try expectGoogleLabels(answer.name.?.full.labels);
    try testing.expectEqual(dns.ResourceType.A, answer.typ);
    try testing.expectEqual(dns.ResourceClass.IN, answer.class);
    try testing.expectEqual(@as(i32, 300), answer.ttl);

    const resource_data = try dns.ResourceData.fromOpaque(
        .A,
        answer.opaque_rdata.?,
        .{},
    );

    try testing.expectEqual(
        dns.ResourceType.A,
        @as(dns.ResourceType, resource_data),
    );

    const addr = @as(*const [4]u8, @ptrCast(&resource_data.A.in.sa.addr)).*;
    try testing.expectEqual(@as(u8, 216), addr[0]);
    try testing.expectEqual(@as(u8, 58), addr[1]);
    try testing.expectEqual(@as(u8, 202), addr[2]);
    try testing.expectEqual(@as(u8, 142), addr[3]);
}

fn encodeBase64(buffer: []u8, source: []const u8) []const u8 {
    const encoded = buffer[0..std.base64.standard.Encoder.calcSize(source.len)];
    return std.base64.standard.Encoder.encode(encoded, source);
}

fn encodePacket(pkt: Packet, encode_buffer: []u8, write_buffer: []u8) ![]const u8 {
    const out = try serialTest(pkt, write_buffer);
    return encodeBase64(encode_buffer, out);
}

test "serialization of google.com/A (question)" {
    const domain = "google.com";
    var name_buffer: [2][]const u8 = undefined;
    const name = try dns.Name.fromString(domain[0..], &name_buffer);

    var questions = [_]dns.Question{.{
        .name = name,
        .typ = .A,
        .class = .IN,
    }};

    var empty = [0]dns.Resource{};

    const packet = dns.Packet{
        .header = .{
            .id = 5189,
            .wanted_recursion = true,
            .z = 2,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &empty,
        .nameservers = &empty,
        .additionals = &empty,
    };

    var encode_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    const encoded = try encodePacket(packet, &encode_buffer, &write_buffer);
    try std.testing.expectEqualSlices(u8, TEST_PKT_QUERY, encoded);
}

fn serialTest(packet: Packet, write_buffer: []u8) ![]u8 {
    const typ = std.io.FixedBufferStream([]u8);
    var stream = typ{ .buffer = write_buffer, .pos = 0 };

    const written_bytes = try packet.writeTo(stream.writer());
    const written_data = stream.getWritten();
    try std.testing.expectEqual(written_bytes, written_data.len);

    return written_data;
}

const FixedStream = std.io.FixedBufferStream([]const u8);
fn deserialTest(packet_data: []const u8) !dns.IncomingPacket {
    var stream = FixedStream{ .buffer = packet_data, .pos = 0 };
    return try dns.helpers.parseFullPacket(
        stream.reader(),
        std.testing.allocator,
        .{},
    );
}

test "convert string to dns type" {
    const parsed = try dns.ResourceType.fromString("AAAA");
    try std.testing.expectEqual(dns.ResourceType.AAAA, parsed);
}

test "names have good sizes" {
    var name_buffer: [10][]const u8 = undefined;
    var name = try dns.Name.fromString("example.com", &name_buffer);

    var buf: [256]u8 = undefined;
    var stream = std.io.FixedBufferStream([]u8){ .buffer = &buf, .pos = 0 };
    const network_size = try name.writeTo(stream.writer());

    // length + data + length + data + null
    try testing.expectEqual(@as(usize, 1 + 7 + 1 + 3 + 1), network_size);
}

test "resources have good sizes" {
    var name_buffer: [10][]const u8 = undefined;
    var name = try dns.Name.fromString("example.com", &name_buffer);

    var resource = dns.Resource{
        .name = name,
        .typ = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = .{ .data = "", .current_byte_count = 0 },
    };

    var buf: [256]u8 = undefined;
    var stream = std.io.FixedBufferStream([]u8){ .buffer = &buf, .pos = 0 };
    const network_size = try resource.writeTo(stream.writer());

    // name + rr (2) + class (2) + ttl (4) + rdlength (2)
    try testing.expectEqual(
        @as(usize, name.networkSize() + 10 + resource.opaque_rdata.?.data.len),
        network_size,
    );
}

// This is a known packet generated by zigdig. It would be welcome to have it
// tested in other libraries.
const PACKET_WITH_RDATA = "FEUBIAAAAAEAAAAABmdvb2dsZQNjb20AAAEAAQAAASwABAEAAH8=";

test "rdata serialization" {
    var name_buffer: [2][]const u8 = undefined;
    const name = try dns.Name.fromString("google.com", &name_buffer);
    var resource_data = dns.ResourceData{
        .A = try std.net.Address.parseIp4("127.0.0.1", 0),
    };

    var opaque_rdata_buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&opaque_rdata_buffer);
    _ = try resource_data.writeTo(stream.writer());
    const opaque_rdata = stream.getWritten();

    var answers = [_]dns.Resource{.{
        .name = name,
        .typ = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = .{ .data = opaque_rdata, .current_byte_count = 0 },
    }};

    var empty_res = [_]dns.Resource{};
    var empty_question = [_]dns.Question{};
    const packet = dns.Packet{
        .header = .{
            .id = 5189,
            .wanted_recursion = true,
            .z = 2,
            .answer_length = 1,
        },
        .questions = &empty_question,
        .answers = &answers,
        .nameservers = &empty_res,
        .additionals = &empty_res,
    };

    var write_buffer: [1024]u8 = undefined;
    const serialized_result = try serialTest(packet, &write_buffer);

    var encode_buffer: [1024]u8 = undefined;
    const encoded_result = encodeBase64(&encode_buffer, serialized_result);
    try std.testing.expectEqualStrings(PACKET_WITH_RDATA, encoded_result);
}
