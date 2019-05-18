const std = @import("std");
const builtin = @import("builtin");

const base64 = std.base64;

const rand = std.rand;
const os = std.os;
const testing = std.testing;
const fmt = std.fmt;
const io = std.io;

const err = @import("error.zig");

const Allocator = std.mem.Allocator;
const OutError = io.SliceOutStream.Error;
const InError = io.SliceInStream.Error;
const DNSError = err.DNSError;

pub const DNSPacketRCode = enum(u4) {
    NoError = 0,
    FmtError,
    ServFail,
    NameErr,
    NotImpl,
    Refused,
};

fn debugWarn(comptime format: []const u8, args: ...) void {
    if (builtin.mode == builtin.Mode.Debug) {
        std.debug.warn("[zigdig debug] " ++ format, args);
    }
}

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

        return size;
    }
};

/// Return the amount of elements as if they were split by `delim`.
fn splitCount(data: []const u8, delim: u8) usize {
    var size: usize = 0;

    for (data) |byte| {
        if (byte == delim) size += 1;
    }

    size += 1;

    return size;
}

/// Get a DNSName out of a domain name.
pub fn toDNSName(allocator: *Allocator, domain: []const u8) !DNSName {
    std.debug.assert(domain.len <= 255);

    var period_count = splitCount(domain, '.');
    var labels: [][]const u8 = try allocator.alloc([]u8, period_count);

    var it = std.mem.separate(domain, ".");
    var labels_idx: usize = 0;

    while (labels_idx < period_count) : (labels_idx += 1) {
        var label = it.next().?;
        labels[labels_idx] = label;
    }

    return DNSName{ .labels = labels[0..] };
}

pub fn nameToStr(allocator: *Allocator, name: DNSName) ![]const u8 {
    return try std.mem.join(allocator, ".", name.labels);
}

test "toDNSName" {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    const domain = "www.google.com";
    var name = try toDNSName(allocator, domain[0..]);
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

pub const OpaqueDNSRData = struct {
    len: u16,
    value: []u8,
};

pub const DNSResource = struct {
    name: DNSName,

    rr_type: u16,
    class: u16,
    ttl: i32,

    // NOTE: this is DIFFERENT from DNSName due to rdlength being an u16,
    // instead of an u8.
    // NOTE: maybe we re-deserialize this one specifically on
    // another section of the source dedicated to specific RDATA
    rdata: OpaqueDNSRData,
};

const LabelComponentTag = enum {
    Pointer,
    Label,
};

const LabelComponent = union(LabelComponentTag) {
    Pointer: [][]const u8,
    Label: []u8,
};

fn inDeserial(deserializer: var, comptime T: type) DNSError!T {
    return deserializer.deserialize(T) catch |deserial_error| {
        debugWarn("got error: {}\n", deserial_error);
        return DNSError.DeserialFail;
    };
}

pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};

    raw_bytes: []const u8,

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answers: []DNSResource,
    pub authority: []DNSResource,
    pub additional: []DNSResource,

    pub allocator: *Allocator,

    /// Caller owns the memory.
    pub fn init(allocator: *Allocator, raw_bytes: []const u8) !DNSPacket {
        if (builtin.mode == builtin.Mode.Debug) {
            debugWarn("packet base64 = '{}'\n", encodeBase64(raw_bytes));
        }
        var self = DNSPacket{
            .header = DNSHeader.init(),

            // keeping the original packet bytes
            // for compression purposes
            .raw_bytes = raw_bytes,
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
                try serializer.serialize(@intCast(u8, label.len));

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

    fn deserializePointer(
        self: *DNSPacket,
        ptr_offset_1: u8,
        deserializer: var,
    ) (DNSError || Allocator.Error)![][]const u8 {
        // we need to read another u8 and merge both ptr_prefix_1 and the
        // u8 we read into an u16

        // the final offset is u14, but we keep it as u16 to prevent having
        // to do too many complicated things.
        var ptr_offset_2 = try inDeserial(deserializer, u8);

        // merge them together
        var ptr_offset: u16 = (ptr_offset_1 << 7) | ptr_offset_2;

        // set first two bits of ptr_offset to zero as they're the
        // pointer prefix bits (which are always 1, which brings problems)
        ptr_offset &= ~u16(1 << 15);
        ptr_offset &= ~u16(1 << 14);

        // we need to make a proper [][]const u8 which means
        // re-deserializing labels but using start_slice instead
        var offset_size_opt = std.mem.indexOf(u8, self.raw_bytes[ptr_offset..], "\x00");

        if (offset_size_opt) |offset_size| {
            var start_slice = self.raw_bytes[ptr_offset .. ptr_offset + (offset_size + 1)];

            var in = io.SliceInStream.init(start_slice);
            var in_stream = &in.stream;
            var new_deserializer = io.Deserializer(
                .Big,
                .Bit,
                InError,
            ).init(in_stream);

            //debugWarn(
            //    "pointer deserial from '{}' (len {})\n",
            //    start_slice,
            //    start_slice.len,
            //);

            // the old (nonfunctional approach) used infferred error sets
            // and a simpleDeserializeName to counteract the problems
            // with just slapping deserializeName in and doing recursion.

            // The problem with inferred error sets is that as soon as you
            // do recursion, the error set of the function isn't fully analyze
            // by the time the compiler runs over the recusrive call.

            // recasting deserializer errors into a DNSError and enforcing
            // an error set on the chain of deserializeName functions fixes
            // the issue.
            var name = try self.deserializeName(&new_deserializer);
            return name.labels;
        } else {
            return DNSError.ParseFail;
        }
    }

    fn deserializeLabel(
        self: *DNSPacket,
        deserializer: var,
    ) (DNSError || Allocator.Error)!?LabelComponent {
        // check if label is a pointer, this byte will contain 11 as the starting
        // point of it
        var ptr_prefix = try inDeserial(deserializer, u8);
        if (ptr_prefix == 0) return null;

        var bit1 = (ptr_prefix & (1 << 7)) != 0;
        var bit2 = (ptr_prefix & (1 << 6)) != 0;

        if (bit1 and bit2) {
            var labels = try self.deserializePointer(ptr_prefix, deserializer);
            return LabelComponent{ .Pointer = labels };
        } else {
            // the ptr_prefix is currently encoding the label's size
            var label = try self.allocator.alloc(u8, ptr_prefix);

            // properly deserialize the slice
            var label_idx: usize = 0;
            while (label_idx < ptr_prefix) : (label_idx += 1) {
                label[label_idx] = try inDeserial(deserializer, u8);
            }

            return LabelComponent{ .Label = label };
        }

        return null;
    }

    /// Deserializes a DNSName, which represents a slice of slice of u8 ([][]u8)
    pub fn deserializeName(
        self: *DNSPacket,
        deserial: var,
    ) (DNSError || Allocator.Error)!DNSName {
        // allocate empty label slice
        var deserializer = deserial;
        var labels: [][]const u8 = try self.allocator.alloc([]u8, 0);
        var labels_idx: usize = 0;

        while (true) {
            var label = try self.deserializeLabel(deserializer);

            if (label) |denulled_label| {
                labels = try self.allocator.realloc(labels, (labels_idx + 1));

                switch (denulled_label) {
                    .Pointer => |label_ptr| {
                        if (labels_idx == 0) {
                            return DNSName{ .labels = label_ptr };
                        } else {
                            // in here we have an existing label in the labels slice, e.g "leah",
                            // and then label_ptr points to a [][]const u8, e.g
                            // [][]const u8{"ns", "cloudflare", "com"}. we
                            // need to copy that, as a suffix, to the existing
                            // labels slice
                            for (label_ptr) |label_ptr_label, idx| {
                                labels[labels_idx] = label_ptr_label;
                                labels_idx += 1;

                                // reallocate to account for the next incoming label
                                if (idx != label_ptr.len - 1) {
                                    labels = try self.allocator.realloc(labels, (labels_idx + 1));
                                }
                            }

                            return DNSName{ .labels = labels };
                        }
                    },
                    .Label => |label_val| labels[labels_idx] = label_val,
                    else => unreachable,
                }
            } else {
                break;
            }

            labels_idx += 1;
        }

        return DNSName{ .labels = labels };
    }

    /// Deserialises DNS RDATA information into an OpaqueDNSRData struct
    /// for later parsing/unparsing.
    fn deserializeRData(self: *DNSPacket, deserializer: var) !OpaqueDNSRData {
        var rdlength = try deserializer.deserialize(u16);
        var rdata = try self.allocator.alloc(u8, rdlength);
        var i: u16 = 0;

        while (i < rdlength) : (i += 1) {
            rdata[i] = try deserializer.deserialize(u8);
        }

        return OpaqueDNSRData{ .len = rdlength, .value = rdata };
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

        while (i < total) : (i += 1) {
            var name = try self.deserializeName(deserializer);
            var rr_type = try deserializer.deserialize(u16);
            var class = try deserializer.deserialize(u16);
            var ttl = try deserializer.deserialize(i32);

            // rdlength and rdata are under deserializeRData
            var rdata = try self.deserializeRData(deserializer);

            rs_list[i] = DNSResource{
                .name = name,
                .rr_type = rr_type,
                .class = class,
                .ttl = ttl,
                .rdata = rdata,
            };
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
        debugWarn("receiving header: {}\n", self.header.as_str());

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
    var stream = &in.stream;
    var deserializer = io.Deserializer(.Big, .Bit, InError).init(stream);
    var pkt = try DNSPacket.init(allocator, buf);
    try deserializer.deserializeInto(&pkt);
    return pkt;
}

// extracted with 'dig google.com a +noedns'
const TEST_PKT_QUERY = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";
const TEST_PKT_RESPONSE = "RM2BgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASwABNg6yo4=";

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var packet = try DNSPacket.init(allocator, ""[0..]);

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

fn decodeBase64(encoded: []const u8) ![]u8 {
    var buf: [0x10000]u8 = undefined;
    var decoded = buf[0..try base64.standard_decoder.calcSize(encoded)];
    try base64.standard_decoder.decode(decoded, encoded);
    return decoded;
}

test "deserialization of original google.com/A" {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var decoded = try decodeBase64(TEST_PKT_QUERY[0..]);
    var pkt = try deserialTest(allocator, decoded);

    std.debug.assert(pkt.header.id == 5189);
    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 0);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 0);

    // TODO: assert values of question slice
}

test "deserialization of reply google.com/A" {
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var decoded = try decodeBase64(TEST_PKT_RESPONSE[0..]);
    var pkt = try deserialTest(allocator, decoded);

    std.debug.assert(pkt.header.qdcount == 1);
    std.debug.assert(pkt.header.ancount == 1);
    std.debug.assert(pkt.header.nscount == 0);
    std.debug.assert(pkt.header.arcount == 0);

    // TODO: assert values of question slice
}

fn encodeBase64(out: []const u8) []const u8 {
    var buffer: [0x10000]u8 = undefined;
    var encoded = buffer[0..base64.Base64Encoder.calcSize(out.len)];
    base64.standard_encoder.encode(encoded, out);

    return encoded;
}

fn encodePacket(pkt: DNSPacket) ![]u8 {
    var out = try serialTest(pkt.allocator, pkt);
    return encodeBase64(out);
}

test "serialization of google.com/A" {
    // setup a random id packet
    var da = std.heap.DirectAllocator.init();
    var arena = std.heap.ArenaAllocator.init(&da.allocator);
    errdefer arena.deinit();
    const allocator = &arena.allocator;

    var pkt = try DNSPacket.init(allocator, ""[0..]);
    pkt.header.id = 5189;
    pkt.header.rd = true;
    pkt.header.z = 2;

    var qname = try toDNSName(allocator, "google.com");

    var question = DNSQuestion{
        .qname = qname,
        .qtype = 1,
        .qclass = 1,
    };

    try pkt.addQuestion(question);

    var encoded = try encodePacket(pkt);
    testing.expectEqualSlices(u8, encoded, TEST_PKT_QUERY);
}
