const std = @import("std");
const root = @import("./dns.zig");

const Name = root.Name;
const ResourceType = root.ResourceType;
const ResourceClass = root.ResourceClass;

pub const ResponseCode = enum(u4) {
    NoError = 0,
    FmtError = 1,
    ServFail = 2,
    NameErr = 3,
    NotImpl = 4,
    Refused = 5,
};

/// Describes the header of a DNS packet.
pub const Header = packed struct {
    /// The ID of the packet. Replies to a packet MUST have the same ID.
    id: u16 = 0,

    /// Query/Response flag
    /// Defines if this is a response packet or not.
    is_response: bool = false,

    /// TODO convert to enum
    opcode: i4 = 0,

    /// Authoritative Answer flag
    /// Only valid in response packets. Specifies if the server
    /// replying is an authority for the domain name.
    aa_flag: bool = false,

    /// TC flag - TrunCation.
    /// If the packet was truncated.
    truncated: bool = false,

    /// RD flag - Recursion Desired.
    /// Must be copied to a response packet. If set, the server
    /// handling the request can pursue the query recursively.
    wanted_recursion: bool = false,

    /// RA flag - Recursion Available
    /// Whether recursive query support is available on the server.
    recursion_available: bool = false,

    /// DO NOT USE. RFC1035 has not assigned anything to the Z bits
    z: u3 = 0,

    /// Response code.
    rcode: ResponseCode = .NoError,

    /// Amount of questions in the packet.
    question_length: u16 = 0,

    /// Amount of answers in the packet.
    answer_length: u16 = 0,

    /// Amount of nameservers in the packet.
    nameserver_length: u16 = 0,

    /// Amount of additional recordsin the packet.
    additional_length: u16 = 0,
};

pub const Question = struct {
    name: Name,
    typ: ResourceType,
    class: ResourceClass,
};

/// DNS resource
pub const Resource = struct {
    name: Name,
    typ: ResourceType,
    class: ResourceClass,

    ttl: i32,

    /// Opaque Resource Data.
    /// Parsing of the data in this is done by a separate package, dns.rdata
    opaque_rdata: []const u8,

    /// Give the size, in bytes, of the binary representation of a resource.
    pub fn size(self: @This()) usize {
        var res_size: usize = 0;

        // name for the resource
        res_size += self.name.size();

        // typ, class, ttl = 3 * u16
        // rdata length is u32
        //
        // TODO(!!!): what size is rdata length actually?
        // synchronize this with serialization.

        res_size += @sizeOf(u16) * 3;
        res_size += @sizeOf(u32);

        // then add the rest of the rdata section
        res_size += self.opaque_rdata.len * @sizeOf(u8);

        return res_size;
    }

    pub fn serialize(self: @This(), serializer: anytype) !void {
        try serializer.serialize(self.name);
        try serializer.serialize(self.typ);
        try serializer.serialize(self.class);
        try serializer.serialize(self.ttl);

        // not doing the cast means it gets serialized as an usize.
        try serializer.serialize(@intCast(u16, self.opaque_rdata.len));
        try serializer.serialize(self.opaque_rdata);
    }
};

pub const Packet = struct {
    header: Header,
    questions: []Question,

    const Self = @This();

    fn sliceSizes(self: Self) usize {
        var pkt_size: usize = 0;

        for (self.questions.items) |question| {
            pkt_size += question.name.size();

            // add both type and class (both u16's)
            pkt_size += @sizeOf(u16);
            pkt_size += @sizeOf(u16);
        }

        // for (self.answers.items) |resource| {
        //     pkt_size += resource.size();
        // }

        // for (self.authority.items) |resource| {
        //     pkt_size += resource.size();
        // }

        // for (self.additional.items) |resource| {
        //     pkt_size += resource.size();
        // }

        return pkt_size;
    }

    /// Returns the size in bytes of the binary representation of the packet.
    pub fn size(self: Self) usize {
        return @sizeOf(Header) + self.sliceSizes();
    }

    pub fn serialize(self: Self, serializer: anytype) !void {
        std.debug.assert(self.header.question_length == self.questions.len);
        // std.debug.assert(self.header.answer_length == self.answers.len);
        // std.debug.assert(self.header.nameserver_length == self.authority.len);
        // std.debug.assert(self.header.additional_length == self.additional.len);

        try serializer.serialize(self.header);

        for (self.questions) |question| {
            try serializer.serialize(question.name);
            try serializer.serialize(question.typ);
            try serializer.serialize(question.class);
        }

        //try self.serializeRList(serializer, self.answers);
        //try self.serializeRList(serializer, self.authority);
        //try self.serializeRList(serializer, self.additional);
    }

    fn deserializePointer(
        self: *Self,
        ptr_offset_1: u8,
        deserializer: anytype,
    ) ![][]const u8 {
        // we need to read another u8 and merge both ptr_prefix_1 and the
        // u8 we read into an u16

        // the final offset is u14, but we keep it as u16 to prevent having
        // to do too many complicated things in regards to deserializer state.
        const ptr_offset_2 = try inDeserial(deserializer, u8);

        // merge them together
        var ptr_offset: u16 = (ptr_offset_1 << 7) | ptr_offset_2;

        // set first two bits of ptr_offset to zero as they're the
        // pointer prefix bits (which are always 1, which brings problems)
        ptr_offset &= ~@as(u16, 1 << 15);
        ptr_offset &= ~@as(u16, 1 << 14);

        // we need to make a proper [][]const u8 which means
        // re-deserializing labels but using start_slice instead
        var offset_size_opt = std.mem.indexOf(u8, self.raw_bytes[ptr_offset..], "\x00");

        if (offset_size_opt) |offset_size| {
            var start_slice = self.raw_bytes[ptr_offset .. ptr_offset + (offset_size + 1)];

            var in = FixedStream{ .buffer = start_slice, .pos = 0 };
            var new_deserializer = DNSDeserializer.init(in.reader());

            // the old (nonfunctional approach) a simpleDeserializeName
            // to counteract the problems with just slapping deserializeName
            // in and doing recursion. however that's problematic as pointers
            // could be pointing to other pointers.

            // because of https://github.com/ziglang/zig/issues/1006
            // and the disallowance of recursive async fns, we heap-allocate this call

            var frame = try self.allocator.create(@Frame(Packet.deserializeName));
            defer self.allocator.destroy(frame);
            frame.* = async self.deserializeName(&new_deserializer);
            var name = try await frame;

            return name.labels;
        } else {
            return Error.ParseFail;
        }
    }

    /// Deserialize the given label into a LabelComponent, which can be either
    /// A Pointer or a full Label.
    fn deserializeLabel(
        self: *Self,
        deserializer: anytype,
    ) (Error || Allocator.Error)!?LabelComponent {
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

    /// Deserializes a DNS Name
    pub fn deserializeName(
        self: *Self,
        deserial: *DNSDeserializer,
    ) (Error || Allocator.Error)!Name {

        // Removing this causes the compiler to send a
        // 'error: recursive function cannot be async'
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
                            return Name{ .labels = label_ptr };
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

                            return Name{ .labels = labels };
                        }
                    },
                    .Label => |label_val| labels[labels_idx] = label_val,
                }
            } else {
                break;
            }

            labels_idx += 1;
        }

        return Name{ .labels = labels };
    }

    pub fn readInto(
        self: *Self,
        reader: anytype,
        ctx: DeserializationContext,
    ) !void {
        const DeserializerType = std.io.Deserializer(.Big, .Bit, @TypeOf(reader));
        var deserializer = try DeserializerType.init(reader);
        self.header = try deserializer.deserialize(Header);

        var questions = try std.ArrayList(Question).init(ctx.allocator);
        self.questions = questions.items;

        var i: usize = 0;
        while (i < self.header.qdcount) {
            // question contains {name, qtype, qclass}
            var name = try self.readName(deserializer, ctx);
            var qtype = try deserializer.deserialize(u16);
            var qclass = try deserializer.deserialize(u16);

            var question = Question{
                .qname = name,
                .qtype = @intToEnum(Type, qtype),
                .qclass = @intToEnum(Class, qclass),
            };

            try questions.append(question);
            i += 1;
        }
    }
};
