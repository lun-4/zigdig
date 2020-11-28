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

    /// Amount of additional records in the packet.
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

const ByteList = std.ArrayList(u8);
const StringList = std.ArrayList([]u8);
const ManyStringList = std.ArrayList([][]u8);

pub const DeserializationContext = struct {
    allocator: *std.mem.Allocator,
    label_pool: StringList,
    name_pool: ManyStringList,
    packet_list: ?ByteList = null,

    const Self = @This();

    pub fn init(allocator: *std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .label_pool = StringList.init(allocator),
            .name_pool = ManyStringList.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.label_pool.items) |label| {
            self.allocator.free(label);
        }

        self.label_pool.deinit();

        for (self.name_pool.items) |item| {
            self.allocator.free(item);
        }

        self.name_pool.deinit();
    }

    pub fn newLabel(self: *Self, length: usize) ![]u8 {
        var newly_allocated = try self.allocator.alloc(u8, length);
        // keep track of newly allocated label for deinitting
        try self.label_pool.append(newly_allocated);
        return newly_allocated;
    }
};

const LabelComponent = union(enum) {
    Full: []const u8,
    Pointer: Name,
    Null: void,
};

fn WrapperReader(comptime ReaderType: anytype) type {
    return struct {
        underlying_reader: ReaderType,
        allocator: *std.mem.Allocator,
        data_list: ByteList,

        const Self = @This();

        pub fn init(underlying_reader: ReaderType, allocator: *std.mem.Allocator) Self {
            return .{
                .underlying_reader = underlying_reader,
                .allocator = allocator,
                .data_list = ByteList.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.list.deinit();
        }

        pub fn read(self: *Self, buffer: []u8) !usize {
            const bytes_read = try self.underlying_reader.read(buffer);
            const bytes = buffer[0..bytes_read];
            try self.data_list.writer().writeAll(bytes);
            return bytes_read;
        }

        pub const Error = ReaderType.Error || error{OutOfMemory};

        pub const Reader = std.io.Reader(*Self, Error, read);

        pub fn reader(self: *Self) Reader {
            return Reader{ .context = self };
        }
    };
}

pub const Packet = struct {
    header: Header,
    questions: []Question,
    answers: []Resource,
    nameservers: []Resource,
    additionals: []Resource,

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

    fn unfoldPointer(
        self: *Self,
        first_offset_component: u8,
        deserializer: anytype,
        ctx: *DeserializationContext,
        /// Buffer that holds the memory for the dns name
        name_buffer: [][]const u8,
        name_index: usize,
    ) anyerror!Name {
        // we need to read another u8 and merge both that and first_offset_component
        // into a u16 we can use as an offset in the entire packet, etc.

        // the final offset is actually 14 bits, the first two are identification
        // of the offset itself.
        const second_offset_component = try deserializer.deserialize(u8);

        // merge them together
        var offset: u16 = (first_offset_component << 7) | second_offset_component;

        // set first two bits of ptr_offset to zero as they're the
        // pointer prefix bits (which are always 1, which brings problems)
        offset &= ~@as(u16, 1 << 15);
        offset &= ~@as(u16, 1 << 14);

        // RFC1035 says:
        //
        // The OFFSET field specifies an offset from
        // the start of the message (i.e., the first octet of the ID field in the
        // domain header).  A zero offset specifies the first byte of the ID field,
        // etc.

        // this mechanism requires us to hold the entire packet in memory
        //
        // one guarantee we have is that pointers can't reference packet
        // offsets in the past (oh than god that makes *some* sense!)

        // to make this work with nicer safety guarantees, we slice the
        // packet bytes we know of, starting on that offset, and ending in the
        // first zero octet we find.
        //
        // if offset is X,
        // then our slice starts at X and ends at X+n, as follows:
        //
        // ... [      0] ...
        //     |      |
        //     X      X+n
        //
        // we just need to calculate n by using indexOf to find the null octet
        //
        // TODO a way to hold the memory we deserialized, maybe a custom
        // wrapper Reader that allocates and stores the bytes it read? i think
        // we already have that kind of thing in std, but i need more time
        var offset_size_opt = std.mem.indexOf(u8, ctx.packet_list.?.items[offset..], "\x00");
        if (offset_size_opt == null) return error.ParseFail;
        var offset_size = offset_size_opt.?;

        // from our slice, we need to read a name from it. we do it via
        // creating a FixedBufferStream, extracting a reader from it, creating
        // a deserializer, and feeding that to readName.
        const label_data = ctx.packet_list.?.items[offset .. offset + (offset_size + 1)];

        const T = std.io.FixedBufferStream([]const u8);
        const InnerDeserializer = std.io.Deserializer(.Big, .Bit, T.Reader);

        var stream = T{
            .buffer = label_data,
            .pos = 0,
        };

        var new_deserializer = InnerDeserializer.init(stream.reader());

        // TODO: no name buffer available here. i think we can create a
        // NameDeserializationContext which holds both the name buffer AND
        // the index so we could keep appending new labels to it
        return self.readName(&new_deserializer, ctx, name_buffer, name_index);
    }

    /// Deserialize a LabelComponent, which can be:
    ///  - a pointer
    ///  - a label
    ///  - a null octet
    fn readLabel(
        self: *Self,
        deserializer: anytype,
        ctx: *DeserializationContext,
        name_buffer: [][]const u8,
        name_index: usize,
    ) !LabelComponent {
        // pointers, in the binary representation of a byte, are as follows
        //  1 1 B B B B B B | B B B B B B B B
        // they are two bytes length, but to identify one, you check if the
        // first two bits are 1 and 1 respectively.
        //
        // then you read the rest, and turn it into an offset (without the
        // starting bits!!!)
        //
        // to prevent inefficiencies, we just read a single bite, see if it
        // has the starting bits, and then we chop it off, merging with the
        // next byte. pointer offsets are 14 bits long
        //
        // when it isn't a pointer, its a length for a given label, and that
        // length can only be a single byte.
        //
        // if the length is 0, its a null octet
        var possible_length = try deserializer.deserialize(u8);
        if (possible_length == 0) return LabelComponent{ .Null = {} };

        // RFC1035:
        // since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.

        var bit1 = (possible_length & (1 << 7)) != 0;
        var bit2 = (possible_length & (1 << 6)) != 0;

        if (bit1 and bit2) {
            // its a pointer!
            var name = try self.unfoldPointer(
                possible_length,
                deserializer,
                ctx,
                name_buffer,
                name_index,
            );
            return LabelComponent{ .Pointer = name };
        } else {
            // those must be 0
            std.debug.assert((!bit1) and (!bit2));

            // the next <possible_length> bytes contain a full label.
            //
            // we use the label pool so we can give a bigger lifetime
            var label = try ctx.newLabel(possible_length);

            var index: usize = 0;
            while (index < possible_length) : (index += 1) {
                label[index] = try deserializer.deserialize(u8);
            }

            return LabelComponent{ .Full = label };
        }
    }

    /// Deserializes a DNS Name
    fn readName(
        self: *Self,
        deserializer: anytype,
        ctx: *DeserializationContext,
        name_buffer: [][]const u8,
        name_index: ?usize,
    ) !Name {
        var buffer_index: usize = name_index orelse 0;

        // RFC1035, 4.1.4 Message Compression:
        // The compression scheme allows a domain name in a message to be
        // represented as either:
        //
        //    - a sequence of labels ending in a zero octet
        //    - a pointer
        //    - a sequence of labels ending with a pointer
        //
        // ==
        //
        // All three of those must end in some way of
        // 	name_buffer[buffer_index] = something;
        // since thats where our result will go.

        // keep attempting to get labels off the deserializer and
        // filling the name_buffer.
        //
        // if it ends in 0, be done
        // if its a pointer, follow pointer
        // if it ends in a pointer, follow pointer
        // else, fill label

        while (true) {
            var component: LabelComponent = try self.readLabel(deserializer, ctx, name_buffer, buffer_index);
            switch (component) {
                .Full => |label| {
                    name_buffer[buffer_index] = label;
                    buffer_index += 1;
                },
                .Pointer => |ptr| {},
                .Null => break,
            }
        }

        return Name{ .labels = name_buffer[0..(buffer_index - 1)] };
    }

    /// (almost) Deserialize an RDATA section. This only deserializes to a slice of u8.
    /// Parsing of RDATA sections are in their own dns.rdata module.
    fn deserializeRData(
        self: *Self,
        deserializer: anytype,
        ctx: *DeserializationContext,
    ) ![]const u8 {
        var rdata_length = try deserializer.deserialize(u16);
        var opaque_rdata = try ctx.allocator.alloc(u8, rdata_length);

        // TODO create dedicated pool for this?
        try ctx.label_pool.append(opaque_rdata);

        var i: u16 = 0;
        while (i < rdata_length) : (i += 1) {
            opaque_rdata[i] = try deserializer.deserialize(u8);
        }

        return opaque_rdata;
    }

    fn deserializeResourceList(
        self: *Self,
        deserializer: anytype,
        ctx: *DeserializationContext,
        length: usize,
        resource_list: *[]Resource,
    ) !void {
        var list = std.ArrayList(Resource).init(ctx.allocator);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            // TODO name buffer stuff
            var name_buffer = try ctx.allocator.alloc([]u8, 32);
            try ctx.name_pool.append(name_buffer);

            var name = try self.readName(deserializer, ctx, name_buffer, null);
            var typ = try deserializer.deserialize(u16);
            var class = try deserializer.deserialize(u16);
            var ttl = try deserializer.deserialize(i32);

            // rdlength and rdata are under deserializeRData
            var opaque_rdata = try self.deserializeRData(deserializer, ctx);

            var resource = Resource{
                .name = name,
                .typ = try std.meta.intToEnum(ResourceType, typ),
                .class = try std.meta.intToEnum(ResourceClass, class),
                .ttl = ttl,
                .opaque_rdata = opaque_rdata,
            };

            try list.append(resource);
        }

        resource_list.* = list.items;
    }

    pub fn readInto(
        self: *Self,
        upstream_reader: anytype,
        ctx: *DeserializationContext,
    ) !void {
        const WrapperReaderType = WrapperReader(@TypeOf(upstream_reader));
        var wrapper_reader = WrapperReaderType.init(upstream_reader, ctx.allocator);
        ctx.packet_list = wrapper_reader.data_list;
        var reader = wrapper_reader.reader();

        const DeserializerType = std.io.Deserializer(.Big, .Bit, @TypeOf(reader));
        var deserializer = DeserializerType.init(reader);
        self.header = try deserializer.deserialize(Header);

        var questions = std.ArrayList(Question).init(ctx.allocator);

        var i: usize = 0;
        while (i < self.header.question_length) {
            var name_buffer = try ctx.allocator.alloc([]u8, 32);
            try ctx.name_pool.append(name_buffer);

            var name = try self.readName(&deserializer, ctx, name_buffer, null);
            var qtype = try deserializer.deserialize(u16);
            var qclass = try deserializer.deserialize(u16);

            var question = Question{
                .name = name,
                .typ = try std.meta.intToEnum(ResourceType, qtype),
                .class = try std.meta.intToEnum(ResourceClass, qclass),
            };

            try questions.append(question);
            i += 1;
        }

        self.questions = questions.items;

        try self.deserializeResourceList(&deserializer, ctx, self.header.answer_length, &self.answers);
        try self.deserializeResourceList(&deserializer, ctx, self.header.nameserver_length, &self.nameservers);
        try self.deserializeResourceList(&deserializer, ctx, self.header.additional_length, &self.additionals);
    }
};
