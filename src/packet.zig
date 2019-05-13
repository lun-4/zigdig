const std = @import("std");
const builtin = @import("builtin");

const rand = std.rand;
const os = std.os;
const testing = std.testing;
const fmt = std.fmt;

const io = std.io;

pub const DNSHeader = packed struct {
    id: u16,
    qr_flag: bool,
    opcode: i4,

    aa_flag: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u3,
    rcode: u4,

    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub fn init() DNSHeader {
        var self = DNSHeader{
            .id = 0,
            .qr_flag = false,
            .opcode = 0,
            .aa_flag = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = 0,
            .qdcount = 0,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };

        return self;
    }

    pub fn as_str(self: *DNSHeader) ![]u8 {
        var buf: [1024]u8 = undefined;
        return fmt.bufPrint(
            &buf,
            "DNSHeader<id={},qd={},an={},ns={},ar={}>",
            self.id,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        );
    }

    pub fn export_out(self: *DNSHeader) []u8 {
        var out: [512]u8 = undefined;
        @memcpy(&out, @ptrCast([*]u8, self), 512);
        return &out;
    }
};

pub const DNSName = struct {
    len: u8,
    name: []u8,
};

pub const DNSQuestion = struct {
    qname: DNSName,
    qtype: u16,
    qclass: u16,
};

pub const DNSResource = struct {
    name: DNSName,

    rr_type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,

    // TODO: generics? maybe?
    rdata: []u8,
};

pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answers: []DNSResource,
    pub authority: []DNSResource,
    pub additional: []DNSResource,

    /// Caller owns the memory.
    pub fn init(allocator: *std.mem.Allocator) !DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),

            .questions = try allocator.alloc(DNSQuestion, 1 << 16),
            .answers = try allocator.alloc(DNSResource, 1 << 16),
            .authority = try allocator.alloc(DNSResource, 1 << 16),
            .additional = try allocator.alloc(DNSResource, 1 << 16),
        };
        return self;
    }

    pub fn as_str(self: *DNSPacket) ![]u8 {
        var buf: [1024]u8 = undefined;
        return try fmt.bufPrint(&buf, "DNSPacket<{}>", self.header.as_str());
    }

    pub fn is_valid(self: *DNSPacket) bool {
        return (self.questions.len == self.header.qdcount and
            self.answers.len == self.header.ancount and
            self.authority.len == self.header.nscount and
            self.additional.len == self.header.arcount);
    }

    pub fn serialize(self: DNSPacket, serializer: var) !void {
        try serializer.serialize(self.header);
    }

    pub fn deserialize(self: *DNSPacket, deserializer: var) !void {
        self.*.header = try deserializer.deserialize(DNSHeader);

        var i: usize = 0;
        while (i < self.*.header.qdcount) {
            i += 1;
        }

        // TODO
        // * read qdcount DNSQuestion.
        // * when reading names, read an u8, then read many other u8's

        // self.*.questions = try deserializer.deserialize([]DNSQuestion);
    }
};

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var packet = try DNSPacket.init(allocator);

    var r = rand.DefaultPrng.init(os.time.timestamp());
    const random_id = r.random.int(u16);
    packet.header.id = random_id;

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    const OutError = io.SliceOutStream.Error;
    const InError = io.SliceInStream.Error;

    var buf: [1024]u8 = undefined;
    var out = io.SliceOutStream.init(buf[0..]);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);

    try serializer.serialize(packet);
    try serializer.flush();

    // deserialize it
    var in = io.SliceInStream.init(buf[0..]);
    var in_stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);
    var new_packet = try deserializer.deserialize(DNSPacket);

    testing.expectEqual(new_packet.header.id, packet.header.id);
}
