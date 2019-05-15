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

pub const DNSPacketRCode = enum(u4) {
    NoError = 0,
    FmtError,
    ServFail,
    NameErr,
    NotImpl,
    Refused,
};

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
            "DNSHeader<{},{},{},{},{},{},{},{},{},{},{},{},{}>",
            self.id,
            self.qr_flag,
            self.opcode,
            self.aa_flag,
            self.tc,
            self.rd,
            self.ra,
            self.z,
            self.rcode,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        );
    }
};

pub const DNSName = struct {
    pub labels: [][]const u8,

    pub fn totalSize(self: *const DNSName) usize {
        // by default, add the null octet at the end of it
        var size: usize = 1;

        for (self.labels) |label| {
            // length octet + the actual label octets
            size += @sizeOf(u8);
            size += label.len * @sizeOf(u8);
        }

        // include null octet
        size += @sizeOf(u8);

        return size;
    }
};

/// Return the amount of elements as if they were split by `delim`.
fn splitCount(comptime data: []const u8, comptime delim: u8) usize {
    var size: usize = 0;

    for (data) |byte| {
        if (byte == delim) size += 1;
    }

    size += 1;

    return size;
}

/// Get a DNSName out of a domain name. This is a comptime operation.
pub fn toDNSName(comptime domain: []const u8) DNSName {
    comptime {
        std.debug.assert(domain.len <= 255);
        var period_count = splitCount(domain, '.');
        var labels: [period_count][]const u8 = undefined;

        var it = std.mem.separate(domain, ".");
        var labels_idx: usize = 0;

        inline while (labels_idx < period_count) : (labels_idx += 1) {
            var label = it.next().?;
            labels[labels_idx] = label;
        }

        return DNSName{ .labels = labels[0..] };
    }
}

test "toDNSName" {
    const domain = "www.google.com";
    var name = toDNSName(domain[0..]);
    std.debug.assert(name.labels.len == 3);
    testing.expect(std.mem.eql(u8, name.labels[0], "www"));
    testing.expect(std.mem.eql(u8, name.labels[1], "google"));
    testing.expect(std.mem.eql(u8, name.labels[2], "com"));
}

pub const DNSQuestion = struct {
    pub qname: DNSName,
    pub qtype: u16,
    pub qclass: u16,
};

pub const DNSRData = struct {
    len: u16,
    value: []u8,
};

pub const DNSResource = struct {
    name: DNSName,

    rr_type: u16,
    class: u16,
    ttl: u32,

    // NOTE: this is DIFFERENT from DNSName due to rdlength being an u16,
    // instead of an u8.
    // NOTE: maybe we re-deserialize this one specifically on
    // another section of the source dedicated to specific RDATA
    rdata: DNSRData,
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

        // TODO: for now, we're only serializing our questions due to this
        // being a client library, not a server library.
        for (self.questions) |question| {
            for (question.qname.labels) |label| {
                try serializer.serialize(label.len);
                for (label) |byte| {
                    try serializer.serialize(byte);
                }
            }

            // null-octet for the end of labels
            try serializer.serialize(u8(0));

            try serializer.serialize(question.qtype);
            try serializer.serialize(question.qclass);
        }
    }

    fn deserializeLengthPrefix(
        self: *DNSPacket,
        comptime T: type,
        comptime V: type,
        deserializer: var,
    ) !V {
        var len = try deserializer.deserialize(T);
        var value = try self.allocator.alloc(u8, len);

        var i: usize = 0;
        while (i < len) : (i += 1) {
            value[i] = try deserializer.deserialize(u8);
        }

        return V{
            .len = len,
            .value = value,
        };
    }

    /// Deserializes a DNSName, which represents a slice of slice of u8 ([][]u8)
    fn deserializeName(self: *DNSPacket, deserializer: var) !DNSName {
        // allocate empty label slice
        var labels: [][]u8 = try self.allocator.alloc([]u8, 0);
        var labels_idx: usize = 0;

        while (true) {
            var label_size = try deserializer.deserialize(u8);
            if (label_size == 0) break;

            // allocate the new label and the new size of labels
            labels = try self.allocator.realloc(labels, (labels_idx + 1));
            var label = try self.allocator.alloc(u8, label_size);
            labels[labels_idx] = label;

            var label_idx: usize = 0;
            while (label_idx < label_size) : (label_idx += 1) {
                label[label_idx] = try deserializer.deserialize(u8);
            }

            labels_idx += 1;
        }

        return DNSName{ .labels = labels };
    }

    fn deserializeRData(self: *DNSPacket, deserializer: var) !DNSRData {
        return try self.deserializeLengthPrefix(u16, DNSRData, deserializer);
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
                } else if (fieldType == DNSRData) {
                    value = try self.deserializeRData(deserializer);
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
        num_elements: usize,
    ) ![]T {
        return try self.allocator.alloc(T, num_elements);
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

    pub fn addQuestion(self: *DNSPacket, question: DNSQuestion) !void {
        // bump it by 1 and realloc the questions slice to handle the new
        // question
        self.header.qdcount += 1;
        self.questions = try self.allocator.realloc(
            self.questions,
            self.header.qdcount,
        );

        // TODO: shouldn't this be a copy of sorts? aren't we allocating
        // more than we should with this?
        self.questions[self.header.qdcount - 1] = question;
    }

    fn resourceSize(self: DNSPacket, resource: DNSResource) usize {
        var res_size: usize = 0;

        // name for the resource
        res_size += resource.name.totalSize();

        // rr_type, class, ttl, rdlength are 3 u16's and one u32.
        res_size += @sizeOf(u16) * 3;
        res_size += @sizeOf(u32);

        // rdata
        res_size += @sizeOf(u16);
        res_size += resource.rdata.len * @sizeOf(u8);

        return res_size;
    }

    fn sliceSizes(self: DNSPacket) usize {
        var extra_size: usize = 0;

        for (self.questions) |question| {
            // DNSName is composed of labels, each label is length-prefixed,
            // so the total amount of bytes is ()
            extra_size += question.qname.totalSize();

            // add both qtype and qclass (both u16's)
            extra_size += @sizeOf(u16);
            extra_size += @sizeOf(u16);
        }

        // TODO: the DNSResource slice sizes
        for (self.answers) |answer| {
            extra_size += self.resourceSize(answer);
        }

        return extra_size;
    }

    /// Returns the size in bytes of the packet for (de)serialization purposes.
    pub fn size(self: DNSPacket) usize {
        return @sizeOf(DNSHeader) + self.sliceSizes();
    }
};

fn serialTest(allocator: *Allocator, packet: DNSPacket) ![]u8 {
    var buf = try allocator.alloc(u8, packet.size());

    var out = io.SliceOutStream.init(buf);
    var out_stream = &out.stream;
    var serializer = io.Serializer(.Big, .Bit, OutError).init(out_stream);

    try serializer.serialize(packet);
    try serializer.flush();
    return buf;
}

fn deserialTest(allocator: *Allocator, buf: []u8) !DNSPacket {
    var in = io.SliceInStream.init(buf);
    var in_stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(in_stream);
    var pkt = try DNSPacket.init(allocator);
    try deserializer.deserializeInto(&pkt);
    return pkt;
}

// extracted with 'dig google.com a +noedns'
const GOOGLE_COM_A_PKT = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";

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
    var buf = try serialTest(allocator, packet);

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

    std.debug.warn("{}\n", pkt.header.as_str());

    std.debug.assert(pkt.header.id == 5189);
    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 0);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 0);
}

test "serialization of google.com/A" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var pkt = try DNSPacket.init(allocator);
    pkt.header.id = 5189;
    pkt.header.rd = true;
    pkt.header.z = 2;

    var qname = toDNSName("google.com");

    var question = DNSQuestion{
        .qname = qname,
        .qtype = 1,
        .qclass = 1,
    };

    try pkt.addQuestion(question);
    var out = try serialTest(allocator, pkt);

    var buffer: [0x10000]u8 = undefined;
    var encoded = buffer[0..base64.Base64Encoder.calcSize(out.len)];
    base64.standard_encoder.encode(encoded, out);

    std.debug.warn("'{}' '{}'", encoded, GOOGLE_COM_A_PKT);

    testing.expectEqualSlices(u8, encoded, GOOGLE_COM_A_PKT);
}
