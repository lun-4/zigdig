const std = @import("std");
const base64 = std.base64;

const rand = std.rand;
const os = std.os;
const testing = std.testing;
const fmt = std.fmt;
const io = std.io;

const Allocator = std.mem.Allocator;
const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;

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
};

pub const DNSName = struct {
    pub len: u8,
    pub value: []u8,
};

pub const DNSQuestion = struct {
    pub qname: DNSName,
    pub qtype: u16,
    pub qclass: u16,
};

pub const DNSResource = struct {
    name: DNSName,

    rr_type: u16,
    class: u16,
    ttl: u32,
    rdlength: u16,

    // it uses the same length-prefix as actual dns names.
    // we can try redeserializing via SliceOutStream
    rdata: DNSName,
};

pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answers: []DNSResource,
    pub authority: []DNSResource,
    pub additional: []DNSResource,

    allocator: *Allocator,

    /// Caller owns the memory.
    pub fn init(allocator: *Allocator) !DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),
            .allocator = allocator,

            .questions = try allocator.alloc(DNSQuestion, 0),
            .answers = try allocator.alloc(DNSResource, 0),
            .authority = try allocator.alloc(DNSResource, 0),
            .additional = try allocator.alloc(DNSResource, 0),
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

    /// Deserializes a DNSName, which represents a length-prefixed slice of u8.
    fn deserializeName(self: *DNSPacket, deserializer: var) !DNSName {
        var len = try deserializer.deserialize(u8);
        var value = try self.allocator.alloc(u8, len);

        var i: usize = 0;

        while (i < len) {
            value[i] = try deserializer.deserialize(u8);
            i += 1;
        }

        return DNSName{
            .len = len,
            .value = value,
        };
    }

    /// Deserialize a list of DNSResource which sizes are controlled by the
    /// header's given count.
    fn deserialResourceList(
        self: *DNSPacket,
        deserializer: var,
        comptime header_field: []const u8,
        comptime target_field: []const u8,
    ) !void {
        var i: usize = 0;
        var total = @field(self.*.header, header_field);
        var rs_list = @field(self.*, target_field);

        while (i < total) {
            const list_type = @typeOf(rs_list);
            const list_info = @typeInfo(list_type).Pointer;
            const info = @typeInfo(list_info.child).Struct;

            //@compileLog(info.fields);

            inline for (info.fields) |field_info| {
                const name = field_info.name;
                const fieldType = field_info.field_type;
                var value: fieldType = undefined;

                // deserializing DNSNames involves allocating a
                // runtime-known string, which means its a pointer,
                // which means its not deserializable BY DEFAULT.
                if (fieldType == DNSName) {
                    value = try self.deserializeName(deserializer);
                } else {
                    value = try deserializer.deserialize(fieldType);
                }

                @field(rs_list[i], name) = value;
            }
            i += 1;
        }
    }

    fn allocSlice(
        self: *DNSPacket,
        comptime T: type,
        size: usize,
    ) ![]T {
        return try self.allocator.alloc(T, size);
    }

    pub fn deserialize(self: *DNSPacket, deserializer: var) !void {
        self.header = try deserializer.deserialize(DNSHeader);

        // allocate the slices based on header data (WHEN DESERIALIZING).
        // when serializing or using addQuestion we do a realloc.
        self.questions = try self.allocSlice(DNSQuestion, self.header.qdcount);
        self.answers = try self.allocSlice(DNSResource, self.header.ancount);
        self.authority = try self.allocSlice(DNSResource, self.header.nscount);
        self.additional = try self.allocSlice(DNSResource, self.header.arcount);

        // deserialize our questions, but since they contain DNSName,
        // the deserialization is messier than what it should be..

        var i: usize = 0;
        while (i < self.header.qdcount) {
            // question contains {name, qtype, qclass}
            var name = try self.deserializeName(deserializer);
            var qtype = try deserializer.deserialize(u16);
            var qclass = try deserializer.deserialize(u16);

            var question = DNSQuestion{
                .qname = name,
                .qtype = qtype,
                .qclass = qclass,
            };

            self.questions[i] = question;
            i += 1;
        }

        try self.deserialResourceList(deserializer, "ancount", "answers");
        try self.deserialResourceList(deserializer, "nscount", "authority");
        try self.deserialResourceList(deserializer, "arcount", "additional");
    }

    fn addQuestion(self: *DNSPacket, question: DNSQuestion) !void {
        // bump it by 1 and realloc the questions slice to handle the new
        // question
        self.*.header.qdcount += 1;
        self.*.questions = try self.allocator.realloc(
            self.*.questions,
            self.*.header.qdcount,
        );

        // TODO: shouldn't this be a copy of sorts? aren't we allocating
        // more than we should with this?
        self.*.questions[self.*.header.qdcount - 1] = question;
    }
};

fn serialTest(packet: DNSPacket) ![]u8 {
    var buf: [0x1000]u8 = undefined;
    var out = io.SliceOutStream.init(buf[0..]);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);

    try serializer.serialize(packet);
    try serializer.flush();
    return buf[0..];
}

fn deserialTest(allocator: *Allocator, buf: []u8) !DNSPacket {
    var in = io.SliceInStream.init(buf);
    var in_stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);
    var pkt = try DNSPacket.init(allocator);
    try deserializer.deserializeInto(&pkt);
    return pkt;
}

const GOOGLE_COM_A_PKT = "dKwBIAABAAAAAAABBmdvb2dsZQNjb20AAAEAAQAAKRAAAAAAAAAMAAoACMNmC6Uunlys";

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var packet = try DNSPacket.init(allocator);

    var r = rand.DefaultPrng.init(os.time.timestamp());
    const random_id = r.random.int(u16);
    packet.header.id = random_id;

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    var buf = try serialTest(packet);

    // deserialize it
    var new_packet = try deserialTest(allocator, buf);

    testing.expectEqual(new_packet.header.id, packet.header.id);
}

test "deserialization of original google.com/A" {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var buf: [0x1000]u8 = undefined;
    var decoded = buf[0..try base64.standard_decoder.calcSize(GOOGLE_COM_A_PKT)];
    try base64.standard_decoder.decode(decoded, GOOGLE_COM_A_PKT);
    var pkt = try deserialTest(allocator, decoded);

    std.debug.assert(pkt.header.id == 29868);
    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 0);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 1);
}

test "serialization of google.com/A" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var pkt = try DNSPacket.init(allocator);
    var question = DNSQuestion{
        .qname = DNSName{
            .len = 10,
            .value = &"google.com",
        },

        .qtype = 1,
        .qclass = 1,
    };

    try pkt.addQuestion(question);
    var out = try serialTest(pkt);

    var buffer: [0x10000]u8 = undefined;
    var encoded = buffer[0..base64.Base64Encoder.calcSize(out.len)];
    base64.standard_encoder.encode(encoded, out);

    testing.expectEqualSlices(u8, encoded, GOOGLE_COM_A_PKT);
}
