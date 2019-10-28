const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");

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
const DNSClass = types.DNSClass;
const DNSType = types.DNSType;

pub const QuestionList = std.ArrayList(DNSQuestion);
pub const ResourceList = std.ArrayList(DNSResource);
pub const DNSDeserializer = io.Deserializer(.Big, .Bit, InError);

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

/// Describes the header of a DNS packet.
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

    /// Initializes a DNSHeader with default values.
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

    /// Returns a "human-friendly" representation of the header for
    /// debugging purposes
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

/// Represents a single DNS domain-name, which is a slice of strings. The
/// "www.google.com" friendly domain name would be represented in DNS as a
/// sequence of labels: first "www", then "google", then "com", with a length
/// prefix for all of them, ending in a null byte.
///
/// Due to DNS pointers, it becomes easier to process [][]const u8 instead of
/// []u8 or []const u8 as you can merge things easily internally.
pub const DNSName = struct {
    labels: [][]const u8,

    /// Returns the total size in bytes of the DNSName as if it was sent
    /// over a socket.
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

    /// Convert a DNSName to a human-friendly domain name.
    /// Does not add a period to the end of it.
    pub fn toStr(self: *const DNSName, allocator: *Allocator) ![]u8 {
        return try std.mem.join(allocator, ".", self.labels);
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

/// Get a DNSName out of a domain name ("www.google.com", for example).
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

test "toDNSName" {
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    const domain = "www.google.com";
    var name = try toDNSName(allocator, domain[0..]);
    std.debug.assert(name.labels.len == 3);
    testing.expect(std.mem.eql(u8, name.labels[0], "www"));
    testing.expect(std.mem.eql(u8, name.labels[1], "google"));
    testing.expect(std.mem.eql(u8, name.labels[2], "com"));
}

/// Represents a DNS question sent on the packet's question list.
pub const DNSQuestion = struct {
    qname: DNSName,
    qtype: DNSType,
    qclass: DNSClass,
};

/// Represents any RDATA information. This is opaque (as a []u8) because RDATA
/// is very different than parsing the packet, as there can be many kinds of
/// DNS types, each with their own RDATA structure. Look over the rdata module
/// for parsing of OpaqueDNSRData into a nicer DNSRData.
pub const OpaqueDNSRData = struct {
    len: u16,
    value: []u8,
};

/// Represents a single DNS resource. Appears on the answer, authority,
/// and additional lists
pub const DNSResource = struct {
    name: DNSName,

    rr_type: DNSType,
    class: DNSClass,
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

/// Represents a Label if it is a pointer to a set of labels OR a single label.
/// DNSName's, by RFC1035 can appear in three ways (in binary form):
///  - As a set of labels, ending with a null byte.
///  - As a set of labels, with a pointer to another set of labels,
///     ending with null.
///  - As a pointer to another set of labels.
/// Recursive parsing is used to convert all pointers into proper labels
/// for nicer usage of the library.
const LabelComponent = union(LabelComponentTag) {
    Pointer: [][]const u8,
    Label: []u8,
};

/// Deserialize a type, but send any error to stderr (if compiled in Debug mode)
/// This is required due to the recusive requirements of DNSName parsing as
/// explained in LabelComponent. Zig as of right now does not allow recursion
/// on functions with infferred error sets, and enforcing an error set
/// (which is the only solution) caused even more problems due to
/// io.Deserializer not giving a stable error set at compile-time.
fn inDeserial(deserializer: var, comptime T: type) DNSError!T {
    return deserializer.deserialize(T) catch |deserial_error| {
        debugWarn("got error: {}\n", deserial_error);
        return DNSError.DeserialFail;
    };
}

/// Give the size, in bytes, of the binary representation of a resource.
fn resourceSize(resource: DNSResource) usize {
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

/// Represents a full DNS packet, including all conversion to and from binary.
/// This struct supports the io.Serializer and io.Deserializer interfaces.
/// The serialization of DNS packets only serializes the question list. Be
/// careful with adding things other than questions, as the header will be
/// modified, but the lists won't appear in the final result.
pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};
    allocator: *Allocator,

    raw_bytes: []const u8,

    header: DNSHeader,
    questions: QuestionList,
    answers: ResourceList,
    authority: ResourceList,
    additional: ResourceList,

    /// Initialize a DNSPacket with an allocator (for internal parsing)
    /// and a raw_bytes slice for pointer deserialization purposes (as they
    /// point to an offset *inside* the existing DNS packet's binary)
    /// Caller owns the memory.
    pub fn init(allocator: *Allocator, raw_bytes: []const u8) DNSPacket {
        debugWarn("packet = {x}\n", raw_bytes);

        var self = DNSPacket{
            .header = DNSHeader.init(),

            // keeping the original packet bytes
            // for compression purposes
            .raw_bytes = raw_bytes,
            .allocator = allocator,

            .questions = QuestionList.init(allocator),
            .answers = ResourceList.init(allocator),
            .authority = ResourceList.init(allocator),
            .additional = ResourceList.init(allocator),
        };
        return self;
    }

    /// Return if this packet makes sense, if the headers' provided lengths
    /// match the lengths of the given packets. This is not checked when
    /// serializing.
    pub fn is_valid(self: *DNSPacket) bool {
        return (self.questions.len == self.header.qdcount and
            self.answers.len == self.header.ancount and
            self.authority.len == self.header.nscount and
            self.additional.len == self.header.arcount);
    }

    /// Serialize a DNSResource list.
    fn serializeRList(
        self: DNSPacket,
        serializer: var,
        rlist: ResourceList,
    ) !void {
        for (rlist.toSlice()) |resource| {
            // serialize the name for the given resource
            try serializer.serialize(resource.name.labels.len);

            for (resource.name.labels) |label| {
                try serializer.serialize(label);
            }

            try serializer.serialize(resource.rr_type);
            try serializer.serialize(resource.class);
            try serializer.serialize(resource.ttl);

            try serializer.serialize(resource.rdata.len);
            try serializer.serialize(resource.rdata.value);
        }
    }

    pub fn serialize(self: DNSPacket, serializer: var) !void {
        try serializer.serialize(self.header);

        for (self.questions.toSlice()) |question| {
            for (question.qname.labels) |label| {
                try serializer.serialize(@intCast(u8, label.len));

                for (label) |byte| {
                    try serializer.serialize(byte);
                }
            }

            // null-octet for the end of labels
            try serializer.serialize(u8(0));

            try serializer.serialize(question.qtype);
            try serializer.serialize(@enumToInt(question.qclass));
        }

        try self.serializeRList(serializer, self.answers);
        try self.serializeRList(serializer, self.authority);
        try self.serializeRList(serializer, self.additional);
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
            var new_deserializer = DNSDeserializer.init(in_stream);

            //debugWarn(
            //    "pointer deserial from '{}' (len {})\n",
            //    start_slice,
            //    start_slice.len,
            //);

            // the old (nonfunctional approach) a simpleDeserializeName
            // to counteract the problems with just slapping deserializeName
            // in and doing recursion. however that's problematic as pointers
            // could be pointing to other pointers.

            // because of issue 1006 and the disallowance of recursive async
            // fns, we heap-allocate this call

            var frame = try self.allocator.create(@Frame(DNSPacket.deserializeName));
            defer self.allocator.destroy(frame);
            frame.* = async self.deserializeName(&new_deserializer);
            var name = try await frame;

            return name.labels;
        } else {
            return DNSError.ParseFail;
        }
    }

    /// Deserialize the given label into a LabelComponent, which can be either
    /// A Pointer or a full Label.
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
        deserial: *DNSDeserializer,
    ) (DNSError || Allocator.Error)!DNSName {
        if (std.io.mode == .evented) {
            _ = @frame();
        }

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
        rs_list: *ResourceList,
    ) !void {
        const total = @field(self.*.header, header_field);

        var i: usize = 0;
        while (i < total) : (i += 1) {
            var name = try self.deserializeName(deserializer);
            var rr_type = try deserializer.deserialize(u16);
            var class = try deserializer.deserialize(u16);
            var ttl = try deserializer.deserialize(i32);

            // rdlength and rdata are under deserializeRData
            var rdata = try self.deserializeRData(deserializer);

            var resource = DNSResource{
                .name = name,
                .rr_type = @intToEnum(DNSType, rr_type),
                .class = @intToEnum(DNSClass, class),
                .ttl = ttl,
                .rdata = rdata,
            };

            try rs_list.append(resource);
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
                .qtype = @intToEnum(DNSType, qtype),
                .qclass = @intToEnum(DNSClass, qclass),
            };

            try self.questions.append(question);
            i += 1;
        }

        try self.deserialResourceList(deserializer, "ancount", &self.answers);
        try self.deserialResourceList(deserializer, "nscount", &self.authority);
        try self.deserialResourceList(deserializer, "arcount", &self.additional);
    }

    pub fn addQuestion(self: *DNSPacket, question: DNSQuestion) !void {
        self.header.qdcount += 1;
        try self.questions.append(question);
    }

    fn sliceSizes(self: DNSPacket) usize {
        var pkt_size: usize = 0;

        for (self.questions.toSlice()) |question| {
            pkt_size += question.qname.totalSize();

            // add both qtype and qclass (both u16's)
            pkt_size += @sizeOf(u16);
            pkt_size += @sizeOf(u16);
        }

        for (self.answers.toSlice()) |answer| {
            pkt_size += resourceSize(answer);
        }

        return pkt_size;
    }

    /// Returns the size in bytes of the binary representation of the packet
    /// for serialization purposes.
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
    var deserializer = DNSDeserializer.init(stream);
    var pkt = DNSPacket.init(allocator, buf);
    try deserializer.deserializeInto(&pkt);
    return pkt;
}

// extracted with 'dig google.com a +noedns'
const TEST_PKT_QUERY = "FEUBIAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ==";
const TEST_PKT_RESPONSE = "RM2BgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASwABNg6yo4=";
const GOOGLE_COM_LABELS = [_][]const u8{ "google"[0..], "com"[0..] };

test "DNSPacket serialize/deserialize" {
    // setup a random id packet
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var packet = DNSPacket.init(allocator, ""[0..]);

    var r = rand.DefaultPrng.init(std.time.timestamp());
    const random_id = r.random.int(u16);
    packet.header.id = random_id;

    // then we'll serialize it under a buffer on the stack,
    // deserialize it, and the header.id should be equal to random_id
    var buf = try serialTest(allocator, packet);

    // deserialize it
    var new_packet = try deserialTest(allocator, buf);

    testing.expectEqual(new_packet.header.id, packet.header.id);

    const fields = [_][]const u8{ "id", "opcode", "qdcount", "ancount" };

    var new_header = new_packet.header;
    var header = packet.header;

    inline for (fields) |field| {
        testing.expectEqual(@field(new_header, field), @field(header, field));
    }
}

fn decodeBase64(encoded: []const u8) ![]u8 {
    var buf: [0x10000]u8 = undefined;
    var decoded = buf[0..try base64.standard_decoder.calcSize(encoded)];
    try base64.standard_decoder.decode(decoded, encoded);
    return decoded;
}

fn expectGoogleLabels(actual: [][]const u8) void {
    for (actual) |label, idx| {
        std.testing.expectEqualSlices(u8, label, GOOGLE_COM_LABELS[idx]);
    }
}

test "deserialization of original google.com/A" {
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
    std.testing.expectEqual(question.qtype, DNSType.A);
    std.testing.expectEqual(question.qclass, DNSClass.IN);
}

test "deserialization of reply google.com/A" {
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
    testing.expectEqual(DNSType.A, question.qtype);
    testing.expectEqual(DNSClass.IN, question.qclass);

    var answer = pkt.answers.at(0);

    expectGoogleLabels(answer.name.labels);
    testing.expectEqual(DNSType.A, answer.rr_type);
    testing.expectEqual(DNSClass.IN, answer.class);
    testing.expectEqual(i32(300), answer.ttl);
}

fn encodeBase64(out: []const u8) []const u8 {
    var buffer: [0x10000]u8 = undefined;
    var encoded = buffer[0..base64.Base64Encoder.calcSize(out.len)];
    base64.standard_encoder.encode(encoded, out);

    return encoded;
}

fn encodePacket(pkt: DNSPacket) ![]const u8 {
    var out = try serialTest(pkt.allocator, pkt);
    return encodeBase64(out);
}

test "serialization of google.com/A" {
    // setup a random id packet
    var arena = std.heap.ArenaAllocator.init(std.heap.direct_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var pkt = DNSPacket.init(allocator, ""[0..]);
    pkt.header.id = 5189;
    pkt.header.rd = true;
    pkt.header.z = 2;

    var qname = try toDNSName(allocator, "google.com");

    var question = DNSQuestion{
        .qname = qname,
        .qtype = DNSType.A,
        .qclass = DNSClass.IN,
    };

    try pkt.addQuestion(question);

    var encoded = try encodePacket(pkt);
    testing.expectEqualSlices(u8, encoded, TEST_PKT_QUERY);
}
