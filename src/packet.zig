const std = @import("std");
const dns = @import("./lib.zig");

const Name = dns.Name;
const ResourceType = dns.ResourceType;
const ResourceClass = dns.ResourceClass;

pub const ResponseCode = enum(u4) {
    NoError = 0,
    FormatError = 1,
    ServFail = 2,
    NameError = 3,
    NotImplemented = 4,
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
    opcode: u4 = 0,

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
    response_code: ResponseCode = .NoError,

    /// Amount of questions in the packet.
    question_length: u16 = 0,

    /// Amount of answers in the packet.
    answer_length: u16 = 0,

    /// Amount of nameservers in the packet.
    nameserver_length: u16 = 0,

    /// Amount of additional records in the packet.
    additional_length: u16 = 0,

    const Self = @This();

    pub fn readFrom(byte_reader: anytype) !Self {
        var self = Self{};

        // turn incoming reader into a bitReader so that we can extract
        // non-u8-aligned data from it
        var reader = std.io.bitReader(.Big, byte_reader);

        const fields = @typeInfo(Self).Struct.fields;
        inline for (fields) |field| {
            var out_bits: usize = undefined;
            @field(self, field.name) = switch (field.type) {
                bool => (try reader.readBits(u1, 1, &out_bits)) > 0,
                u3 => try reader.readBits(u3, 3, &out_bits),
                u4 => try reader.readBits(u4, 4, &out_bits),
                ResponseCode => blk: {
                    const tag_int = try reader.readBits(u4, 4, &out_bits);
                    break :blk try std.meta.intToEnum(ResponseCode, tag_int);
                },
                u16 => try byte_reader.readIntBig(field.type),
                else => @compileError(
                    "unsupported type on header " ++ @typeName(field.type),
                ),
            };
        }
        return self;
    }

    pub fn writeTo(self: Self, byte_writer: anytype) !usize {
        var writer = std.io.bitWriter(.Big, byte_writer);

        const fields = @typeInfo(Self).Struct.fields;
        inline for (fields) |field| {
            const value = @field(self, field.name);
            switch (field.type) {
                bool => try writer.writeBits(@as(u1, if (value) 1 else 0), 1),
                u3 => try writer.writeBits(value, 3),
                u4 => try writer.writeBits(value, 4),
                ResponseCode => try writer.writeBits(@enumToInt(value), 4),
                u16 => try writer.writeBits(value, 16),
                else => @compileError(
                    "unsupported type on header " ++ @typeName(field.type),
                ),
            }
        }

        try writer.flushBits();
        return 3; // TODO make this dynamic on amount given to bitwriter
    }
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

    pub fn writeTo(self: @This(), writer: anytype) !usize {
        const name_size = try self.name.writeTo(writer);
        const typ_size = try self.typ.writeTo(writer);
        const class_size = try self.class.writeTo(writer);
        const ttl_size = 32 / 8;
        try writer.writeIntBig(i32, self.ttl);

        const rdata_prefix_size = 16 / 8;
        try writer.writeIntBig(u16, @intCast(u16, self.opaque_rdata.len));
        const rdata_size = try writer.write(self.opaque_rdata);

        return name_size + typ_size + class_size + ttl_size + rdata_prefix_size + rdata_size;
    }
};

const ByteList = std.ArrayList(u8);
const StringList = std.ArrayList([]u8);
const ManyStringList = std.ArrayList([][]const u8);

pub const DeserializationContext = struct {
    allocator: *std.mem.Allocator,
    label_pool: StringList,
    name_pool: ManyStringList,
    packet_list: ByteList,

    const Self = @This();

    pub fn init(allocator: *std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .label_pool = StringList.init(allocator),
            .name_pool = ManyStringList.init(allocator),
            .packet_list = ByteList.init(allocator),
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

        self.packet_list.deinit();
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
        ctx: *DeserializationContext,

        const Self = @This();

        pub fn init(
            underlying_reader: ReaderType,
            ctx: *DeserializationContext,
        ) Self {
            return .{
                .underlying_reader = underlying_reader,
                .ctx = ctx,
            };
        }

        pub fn read(self: *Self, buffer: []u8) !usize {
            const bytes_read = try self.underlying_reader.read(buffer);
            const bytes = buffer[0..bytes_read];
            try self.ctx.packet_list.writer().writeAll(bytes);
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

    fn writeResourceListTo(resource_list: []Resource, writer: anytype) !usize {
        var size: usize = 0;
        for (resource_list) |resource| {
            size += try resource.writeTo(writer);
        }
        return size;
    }

    pub fn writeTo(self: Self, writer: anytype) !usize {
        std.debug.assert(self.header.question_length == self.questions.len);
        std.debug.assert(self.header.answer_length == self.answers.len);
        std.debug.assert(self.header.nameserver_length == self.nameservers.len);
        std.debug.assert(self.header.additional_length == self.additionals.len);

        const header_size = try self.header.writeTo(writer);

        var question_size: usize = 0;

        for (self.questions) |question| {
            const question_name_size = try question.name.writeTo(writer);
            const question_typ_size = try question.typ.writeTo(writer);
            const question_class_size = try question.class.writeTo(writer);

            question_size += question_name_size + question_typ_size + question_class_size;
        }

        const answers_size = try Self.writeResourceListTo(self.answers, writer);
        const nameservers_size = try Self.writeResourceListTo(self.nameservers, writer);
        const additionals_size = try Self.writeResourceListTo(self.additionals, writer);

        return header_size + question_size +
            answers_size + nameservers_size + additionals_size;
    }

    fn unfoldPointer(
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
        var offset_size_opt = std.mem.indexOf(u8, ctx.packet_list.items[offset..], "\x00");
        if (offset_size_opt == null) return error.ParseFail;
        var offset_size = offset_size_opt.?;

        // from our slice, we need to read a name from it. we do it via
        // creating a FixedBufferStream, extracting a reader from it, creating
        // a deserializer, and feeding that to readName.
        const label_data = ctx.packet_list.items[offset .. offset + (offset_size + 1)];

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
        return Self.readName(&new_deserializer, ctx, name_buffer, name_index);
    }

    /// Deserialize a LabelComponent, which can be:
    ///  - a pointer
    ///  - a full label ([]const u8)
    ///  - a null octet
    fn readLabelComponent(
        reader: anytype,
        allocator: std.mem.Allocator,
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
        var possible_length = try reader.readIntBig(u8);
        if (possible_length == 0) return LabelComponent{ .Null = {} };

        // RFC1035:
        // since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.

        var bit1 = (possible_length & (1 << 7)) != 0;
        var bit2 = (possible_length & (1 << 6)) != 0;

        if (bit1 and bit2) {
            // its a pointer!
            //var name = try Self.unfoldPointer(
            //    possible_length,
            //    deserializer,
            //    ctx,
            //    name_buffer,
            //    name_index,
            //);
            //return LabelComponent{ .Pointer = name };
            return error.TODO;
        } else {
            // those must be 0
            std.debug.assert((!bit1) and (!bit2));

            // the next <possible_length> bytes contain a full label.
            var label = try allocator.alloc(u8, possible_length);
            const read_bytes = try reader.read(label);
            std.debug.assert(read_bytes == label.len);
            return LabelComponent{ .Full = label };
        }
    }

    const ReadNameOptions = struct {
        max_label_count: usize = 128,
    };

    fn readName(
        self: Self,
        reader: anytype,
        allocator: std.mem.Allocator,
        options: ReadNameOptions,
    ) !Name {
        _ = self;
        // RFC1035, 4.1.4 Message Compression:
        // The compression scheme allows a domain name in a message to be
        // represented as either:
        //
        //    - a sequence of labels ending in a zero octet
        //    - a pointer
        //    - a sequence of labels ending with a pointer
        //

        // process incoming components (FullLabel, PointerToLabel, Null) from reader

        var name_buffer = std.ArrayList([]const u8).init(allocator);
        defer name_buffer.deinit();

        while (true) {
            if (name_buffer.items.len > options.max_label_count)
                return error.Overflow;

            const component = try Self.readLabelComponent(reader, allocator);
            switch (component) {
                .Full => |label| try name_buffer.append(label),
                .Pointer => |pointer| {
                    _ = pointer;
                    return error.TODO;
                    //const label = try self.resolveLabelPointer(pointer);
                    //try name_buffer.append(label);
                },
                .Null => break,
            }
        }

        return Name{ .labels = try name_buffer.toOwnedSlice() };
    }

    /// Extract an RDATA. This only spits out a slice of u8.
    /// Parsing of RDATA sections are in the dns.rdata module.
    ///
    /// Caller owns returned memory.
    fn readResourceDataFrom(
        reader: anytype,
        allocator: std.mem.Allocator,
    ) ![]const u8 {
        const rdata_length = try reader.readIntBig(u16);
        var opaque_rdata = try allocator.alloc(u8, rdata_length);
        const read_bytes = try reader.read(opaque_rdata);
        std.debug.assert(read_bytes == opaque_rdata.len);
        return opaque_rdata;
    }

    fn readResourceListFrom(
        self: Self,
        reader: anytype,
        allocator: std.mem.Allocator,
        resource_count: usize,
    ) ![]Resource {
        var list = std.ArrayList(Resource).init(allocator);

        var i: usize = 0;
        while (i < resource_count) : (i += 1) {
            var name = try self.readName(reader, allocator, .{});
            var typ = try reader.readEnum(ResourceType, .Big);
            var class = try reader.readEnum(ResourceClass, .Big);
            var ttl = try reader.readIntBig(i32);
            var opaque_rdata = try Self.readResourceDataFrom(reader, allocator);

            var resource = Resource{
                .name = name,
                .typ = typ,
                .class = class,
                .ttl = ttl,
                .opaque_rdata = opaque_rdata,
            };

            try list.append(resource);
        }

        return try list.toOwnedSlice();
    }

    pub fn readFrom(
        reader: anytype,
        allocator: std.mem.Allocator,
    ) !IncomingPacket {
        // TODO endianess on Header
        var packet = try allocator.create(Self);
        errdefer allocator.destroy(packet);

        packet.header = try Header.readFrom(reader);

        var questions = std.ArrayList(Question).init(allocator);

        var i: usize = 0;
        while (i < packet.header.question_length) {
            var name = try packet.readName(reader, allocator, .{});
            var qtype = try reader.readEnum(ResourceType, .Big);
            var qclass = try reader.readEnum(ResourceClass, .Big);

            var question = Question{
                .name = name,
                .typ = qtype,
                .class = qclass,
            };

            try questions.append(question);
            i += 1;
        }

        packet.questions = try questions.toOwnedSlice();
        packet.answers = try packet.readResourceListFrom(
            reader,
            allocator,
            packet.header.answer_length,
        );
        packet.nameservers = try packet.readResourceListFrom(
            reader,
            allocator,
            packet.header.nameserver_length,
        );
        packet.additionals = try packet.readResourceListFrom(
            reader,
            allocator,
            packet.header.additional_length,
        );

        return IncomingPacket{ .packet = packet, .allocator = allocator };
    }
};

pub const IncomingPacket = struct {
    allocator: std.mem.Allocator,
    packet: *Packet,

    fn freeResource(self: @This(), resource: Resource) void {
        self.allocator.free(resource.name.labels);
        self.allocator.free(resource.opaque_rdata);
    }

    pub fn deinit(self: @This()) void {
        for (self.packet.questions) |question| {
            self.allocator.free(question.name.labels);
        }
        for (self.packet.answers) |resource| self.freeResource(resource);
        for (self.packet.nameservers) |resource| self.freeResource(resource);
        for (self.packet.additionals) |resource| self.freeResource(resource);
        self.allocator.destroy(self.packet);
    }
};
