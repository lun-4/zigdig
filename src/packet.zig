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

// TODO
pub const DNSQuestion = packed struct {
    pub fn export_out(self: *DNSQuestion) []u8 {
        return "";
    }
};

pub const DNSResource = packed struct {
    pub fn export_out(self: *DNSResource) []u8 {
        return "";
    }
};

pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answers: []DNSResource,
    pub authority: []DNSResource,
    pub additional: []DNSResource,

    pub fn init() DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),
            .questions = []DNSQuestion{},
            .answers = []DNSResource{},
            .authority = []DNSResource{},
            .additional = []DNSResource{},
        };
        return self;
    }

    pub fn fill(self: *DNSPacket, ptr: []u8) void {
        // TODO deserializer
    }

    pub fn as_str(self: *DNSPacket) ![]u8 {
        var buf: [1024]u8 = undefined;
        return try fmt.bufPrint(&buf, "DNSPacket<{}>", self.header.as_str());
    }

    pub fn is_valid(self: *DNSPacket) bool {
        var valid = (self.questions.len == self.header.qdcount and
            self.answers.len == self.header.ancount and
            self.authority.len == self.header.nscount and
            self.additional.len == self.header.arcount);
        return valid;
    }

    pub fn serialize(self: DNSPacket, serializer: var) !void {
        try serializer.serialize(self.header);
    }

    pub fn deserialize(self: *DNSPacket, deserializer: var) !void {
        self.*.header = try deserializer.deserialize(DNSHeader);
    }
};

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var packet = DNSPacket.init();
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

    std.debug.warn("\nexported: ({}) '{}'\n", buf.len, buf);

    // deserialize it
    var in = io.SliceInStream.init(buf[0..]);
    var in_stream = &in.stream;

    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);

    var new_packet = try deserializer.deserialize(DNSPacket);

    testing.expectEqual(new_packet.header.id, packet.header.id);
}
