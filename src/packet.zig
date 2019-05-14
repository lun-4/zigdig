const std = @import("std");
const builtin = @import("builtin");

const rand = std.rand;
const os = std.os;
const testing = std.testing;
const fmt = std.fmt;
const io = std.io;
const Allocator = std.mem.Allocator;

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
    pub questions: ?[]DNSQuestion,
    pub answers: ?[]DNSResource,
    pub authority: ?[]DNSResource,
    pub additional: ?[]DNSResource,

    allocator: *Allocator,

    /// Caller owns the memory.
    pub fn init(allocator: *Allocator) DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),
            .allocator = allocator,

            .questions = null,
            .answers = null,
            .authority = null,
            .additional = null,
        };
        return self;
    }

    pub fn as_str(self: *DNSPacket) ![]u8 {
        var buf: [1024]u8 = undefined;
        return try fmt.bufPrint(&buf, "DNSPacket<{}>", self.header.as_str());
    }

    pub fn is_valid(self: *DNSPacket) bool {
        return (self.questions.?.len == self.header.qdcount and
            self.answers.?.len == self.header.ancount and
            self.authority.?.len == self.header.nscount and
            self.additional.?.len == self.header.arcount);
    }

    pub fn serialize(self: DNSPacket, serializer: var) !void {
        try serializer.serialize(self.header);
    }

    /// Deserializes a DNSName, which represents a length-prefixed slice of u8.
    fn deserializeName(self: *DNSPacket, deserializer: var) !DNSName {
        var len = try deserializer.deserialize(u8);
        var value = try self.*.allocator.alloc(u8, len);

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
            const optional_type = @typeOf(rs_list);
            const list_type = @typeInfo(optional_type).Optional.child;
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

                @field(rs_list.?[i], name) = value;
            }
            i += 1;
        }
    }

    fn allocSlice(
        self: *DNSPacket,
        comptime field_name: []const u8,
        comptime T: type,
        size: usize,
    ) !void {
        @field(self.*, field_name) = try self.allocator.alloc(T, size);
    }

    pub fn deserialize(self: *DNSPacket, deserializer: var) !void {
        self.*.header = try deserializer.deserialize(DNSHeader);

        // allocate the slices based on header data
        try self.allocSlice("questions", DNSQuestion, self.*.header.qdcount);
        try self.allocSlice("answers", DNSResource, self.*.header.ancount);
        try self.allocSlice("authority", DNSResource, self.*.header.nscount);
        try self.allocSlice("additional", DNSResource, self.*.header.arcount);

        // deserialize our questions, but since they contain DNSName,
        // the deserialization is messier than what it should be..

        var i: usize = 0;
        while (i < self.*.header.qdcount) {
            i += 1;

            // question contains {name, qtype, qclass}
            var name = try self.deserializeName(deserializer);
            var qtype = try deserializer.deserialize(u16);
            var qclass = try deserializer.deserialize(u16);

            var question = DNSQuestion{
                .qname = name,
                .qtype = qtype,
                .qclass = qclass,
            };

            self.*.questions.?[i] = question;
        }

        try self.deserialResourceList(deserializer, "ancount", "answers");
        try self.deserialResourceList(deserializer, "nscount", "authority");
        try self.deserialResourceList(deserializer, "arcount", "additional");
    }

    fn addQuestion(self: *DNSPacket, question: DNSQuestion) !void {
        // bump it by 1 and realloc the questions slice to handle the new
        // question
        self.*.header.qdcount += 1;
        if (self.*.questions) |questions| {
            self.*.questions = try self.allocator.realloc(
                questions,
                self.*.header.qdcount,
            );

            // TODO: shouldn't this be a copy of sorts? aren't we allocating
            // more than we should with this?
            questions[self.*.header.qdcount - 1] = question;
        } else {
            // starting case where we need to allocate the question slice
            self.*.questions = try self.allocator.alloc(DNSQuestion, 1);
            self.*.questions.?[0] = question;
        }
    }
};

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var packet = DNSPacket.init(allocator);

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
