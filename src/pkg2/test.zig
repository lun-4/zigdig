const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const io = std.io;
const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;

const dns = @import("./dns.zig");
const rdata = dns.rdata;
const Packet = dns.Packet;

test "convert domain string to dns name" {
    const domain = "www.google.com";
    var name_buffer: [3][]const u8 = undefined;
    var name = try dns.Name.fromString(domain[0..], &name_buffer);
    std.debug.assert(name.labels.len == 3);
    testing.expect(std.mem.eql(u8, name.labels[0], "www"));
    testing.expect(std.mem.eql(u8, name.labels[1], "google"));
    testing.expect(std.mem.eql(u8, name.labels[2], "com"));
}

test "convert domain string to dns name (buffer underrun)" {
    const domain = "www.google.com";
    var name_buffer: [1][]const u8 = undefined;
    _ = dns.Name.fromString(domain[0..], &name_buffer) catch |err| switch (err) {
        error.Underflow => {},
        else => return err,
    };
}

// extracted with 'dig google.com a +noedns'
const TEST_PKT_QUERY = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";
const TEST_PKT_RESPONSE = "RM2BgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASwABNg6yo4=";
const GOOGLE_COM_LABELS = [_][]const u8{ "google"[0..], "com"[0..] };

test "Packet serialize/deserialize" {
    var allocator_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = allocator_instance.deinit();
    }
    const allocator = &allocator_instance.allocator;

    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);

    const random_id = r.random.int(u16);
    var packet = dns.Packet{
        .header = .{ .id = random_id },
        .questions = &[_]dns.Question{},
    };

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    var buf = try serialTest(packet);

    // deserialize it and compare if everythings' equal
    var workmem: [1024]u8 = undefined;
    var deserialized = try deserialTest(buf, &workmem);

    testing.expectEqual(deserialized.header.id, packet.header.id);

    const fields = [_][]const u8{ "id", "opcode", "question_length", "answer_length" };

    var new_header = deserialized.header;
    var header = packet.header;

    inline for (fields) |field| {
        testing.expectEqual(@field(new_header, field), @field(header, field));
    }
}

fn decodeBase64(encoded: []const u8) ![]u8 {
    var buf: [0x10000]u8 = undefined;
    var decoded = buf[0..try std.base64.standard_decoder.calcSize(encoded)];
    try std.base64.standard_decoder.decode(decoded, encoded);
    return decoded;
}

fn expectGoogleLabels(actual: [][]const u8) void {
    for (actual) |label, idx| {
        std.testing.expectEqualSlices(u8, label, GOOGLE_COM_LABELS[idx]);
    }
}

test "deserialization of original google.com/A" {
    if (true) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var decoded = try decodeBase64(TEST_PKT_QUERY[0..]);
    var pkt = try deserialTest(allocator, decoded);

    std.debug.assert(pkt.header.id == 5189);
    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 0);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 0);

    const question = pkt.questions.at(0);

    expectGoogleLabels(question.qname.labels);
    std.testing.expectEqual(question.qtype, dns.Type.A);
    std.testing.expectEqual(question.qclass, dns.Class.IN);
}

test "deserialization of reply google.com/A" {
    if (true) return error.SkipZigTest;

    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var decoded = try decodeBase64(TEST_PKT_RESPONSE[0..]);
    var pkt = try deserialTest(allocator, decoded);

    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 1);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 0);

    var question = pkt.questions.at(0);

    expectGoogleLabels(question.qname.labels);
    testing.expectEqual(dns.Type.A, question.qtype);
    testing.expectEqual(dns.Class.IN, question.qclass);

    var answer = pkt.answers.at(0);

    expectGoogleLabels(answer.name.labels);
    testing.expectEqual(dns.Type.A, answer.rr_type);
    testing.expectEqual(dns.Class.IN, answer.class);
    testing.expectEqual(@as(i32, 300), answer.ttl);

    var answer_rdata = try rdata.deserializeRData(pkt, answer);
    testing.expectEqual(dns.Type.A, @as(dns.Type, answer_rdata));

    const addr = @ptrCast(*[4]u8, &answer_rdata.A.in.addr).*;
    testing.expectEqual(@as(u8, 216), addr[0]);
    testing.expectEqual(@as(u8, 58), addr[1]);
    testing.expectEqual(@as(u8, 202), addr[2]);
    testing.expectEqual(@as(u8, 142), addr[3]);
}

fn encodeBase64(buffer: []u8, out: []const u8) []const u8 {
    var encoded = buffer[0..std.base64.Base64Encoder.calcSize(out.len)];
    std.base64.standard_encoder.encode(encoded, out);

    return encoded;
}

fn encodePacket(buffer: []u8, pkt: Packet) ![]const u8 {
    var out = try serialTest(pkt);
    return encodeBase64(buffer, out);
}

test "serialization of google.com/A (question)" {
    const domain = "google.com";
    var name_buffer: [2][]const u8 = undefined;
    var name = try dns.Name.fromString(domain[0..], &name_buffer);

    var packet = dns.Packet{
        .header = .{
            .id = 5189,
            .wanted_recursion = true,
            .z = 2,
            .question_length = 1,
        },
        .questions = &[_]dns.Question{.{
            .name = name,
            .typ = .A,
            .class = .IN,
        }},
    };

    var buffer: [256]u8 = undefined;
    var encoded = try encodePacket(&buffer, packet);
    testing.expectEqualSlices(u8, encoded, TEST_PKT_QUERY);
}

fn serialTest(packet: Packet) ![]u8 {
    var buf: [1024]u8 = undefined;
    const T = std.io.FixedBufferStream([]u8);

    var buffer = T{ .buffer = &buf, .pos = 0 };
    var serializer = io.Serializer(.Big, .Bit, T.Writer).init(buffer.writer());

    try serializer.serialize(packet);
    try serializer.flush();

    return buffer.getWritten();
}

const FixedStream = std.io.FixedBufferStream([]const u8);
const DNSDeserializer = std.io.Deserializer(.Big, .Bit, FixedStream.Reader);

fn deserialTest(buf: []u8, packet_buffer: []u8) !Packet {
    var stream = FixedStream{ .buffer = buf, .pos = 0 };

    var fba = std.heap.FixedBufferAllocator.init(packet_buffer);
    var ctx = dns.DeserializationContext.init(&fba.allocator);

    var pkt = dns.Packet{ .header = .{}, .questions = &[_]dns.Question{} };
    try pkt.readInto(stream.reader(), &ctx);

    return pkt;
}

test "convert string to dns type" {
    var parsed = try dns.ResourceType.fromString("AAAA");
    testing.expectEqual(dns.ResourceType.AAAA, parsed);
}

test "size() methods are good" {
    var name_buffer: [10][]const u8 = undefined;
    var name = try dns.Name.fromString("example.com", &name_buffer);

    // length + data + length + data + null
    testing.expectEqual(@as(usize, 1 + 7 + 1 + 3 + 1), name.size());

    var resource = dns.Resource{
        .name = name,
        .typ = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = "",
    };

    // name + rr (2) + class (2) + ttl (4) + rdlength (2)
    testing.expectEqual(@as(usize, name.size() + 10 + resource.opaque_rdata.len), resource.size());
}

// This is a known packet generated by zigdig. It would be welcome to have it
// tested in other libraries.
const SERIALIZED_PKT = "FEUBIAAAAAEAAAAABmdvb2dsZQNjb20AAAEAAQAAASwABAEAAH8=";

test "rdata serialization" {
    if (true) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var pkt = dns.Packet.init(allocator, ""[0..]);
    pkt.header.id = 5189;
    pkt.header.rd = true;
    pkt.header.z = 2;

    var name = try dns.Name.fromString(allocator, "google.com");
    var pkt_rdata = dns.rdata.DNSRData{
        .A = try std.net.Address.parseIp4("127.0.0.1", 0),
    };

    var rdata_buffer = try allocator.alloc(u8, 0x10000);
    var opaque_rdata = rdata_buffer[0..pkt_rdata.size()];
    var out = io.SliceOutStream.init(rdata_buffer);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);
    try rdata.serializeRData(pkt_rdata, &serializer);

    try pkt.addAnswer(dns.Resource{
        .name = name,
        .rr_type = .A,
        .class = .IN,
        .ttl = 300,
        .opaque_rdata = opaque_rdata,
    });

    var buffer: [128]u8 = undefined;
    var res = try encodePacket(&buffer, pkt);
    testing.expectEqualSlices(u8, res, SERIALIZED_PKT);
}
