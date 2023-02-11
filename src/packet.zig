const std = @import("std");
const dns = @import("./lib.zig");

const Name = dns.Name;
const ResourceType = dns.ResourceType;
const ResourceClass = dns.ResourceClass;

const logger = std.log.scoped(.dns_packet);

/// Represents the response code of the packet.
///
/// RCODE, in https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const ResponseCode = enum(u4) {
    NoError = 0,

    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,

    /// Server failure - The name server was unable to process this query
    /// due to a problem with the name server.
    ServerFailure = 2,

    /// Name Error - Meaningful only for responses from an authoritative name
    /// server, this code signifies that the domain name referenced in
    /// the query does not exist.
    NameError = 3,

    /// Not Implemented - The name server does not support the requested
    /// kind of query.
    NotImplemented = 4,

    /// Refused - The name server refuses to perform the specified
    /// operation for policy reasons.  For example, a name server may not
    /// wish to provide the information to the particular requester,
    /// or a name server may not wish to perform a particular operation
    /// (e.g., zone transfer) for particular data.
    Refused = 5,
};

/// OPCODE from https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
///
/// This value is set by the originator of a query and copied into the response.
pub const OpCode = enum(u4) {
    /// a standard query (QUERY)
    Query = 0,
    /// an inverse query (IQUERY)
    InverseQuery = 1,
    /// a server status request (STATUS)
    ServerStatusRequest = 2,

    // rest is unused as per RFC1035
};

/// Describes the header of a DNS packet.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub const Header = packed struct {
    /// The ID of the packet. Replies to a packet MUST have the same ID.
    id: u16 = 0,

    /// Query/Response flag
    /// Defines if this is a response packet or not.
    is_response: bool = false,

    /// specifies kind of query in this message.
    opcode: OpCode = .Query,

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

    /// Read a header from its network representation in a stream.
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
                OpCode, ResponseCode => blk: {
                    const tag_int = try reader.readBits(u4, 4, &out_bits);
                    break :blk try std.meta.intToEnum(field.type, tag_int);
                },
                u16 => try byte_reader.readIntBig(field.type),
                else => @compileError(
                    "unsupported type on header " ++ @typeName(field.type),
                ),
            };
        }
        return self;
    }

    /// Write the network representation of a header to the given writer.
    pub fn writeTo(self: Self, byte_writer: anytype) !usize {
        var writer = std.io.bitWriter(.Big, byte_writer);

        var written_bits: usize = 0;

        const fields = @typeInfo(Self).Struct.fields;
        inline for (fields) |field| {
            const value = @field(self, field.name);
            written_bits += @bitSizeOf(field.type);
            switch (field.type) {
                bool => try writer.writeBits(@as(u1, if (value) 1 else 0), 1),
                u3 => try writer.writeBits(value, 3),
                u4 => try writer.writeBits(value, 4),
                OpCode, ResponseCode => try writer.writeBits(@enumToInt(value), 4),
                u16 => try writer.writeBits(value, 16),
                else => @compileError(
                    "unsupported type on header " ++ @typeName(field.type),
                ),
            }
        }

        try writer.flushBits();
        const written_bytes = written_bits / 8;
        std.debug.assert(written_bytes == 12);
        return written_bytes;
    }
};

/// Represents a DNS question.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
pub const Question = struct {
    name: ?dns.Name,
    typ: ResourceType,
    class: ResourceClass = .IN,

    const Self = @This();

    pub fn readFrom(reader: anytype, options: dns.ParserOptions) !Self {
        // TODO assert reader is WrapperReader
        logger.debug(
            "reading question at {d} bytes",
            .{reader.context.ctx.current_byte_count},
        );

        var name = try Name.readFrom(reader, options);
        var qtype = try reader.readEnum(ResourceType, .Big);
        var qclass = try ResourceClass.readFrom(reader);

        return Self{
            .name = name,
            .typ = qtype,
            .class = qclass,
        };
    }
};

/// DNS resource
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
pub const Resource = struct {
    name: ?dns.Name,
    typ: ResourceType,
    class: ResourceClass,

    ttl: i32,

    /// Opaque Resource Data. This holds the bytes representing the RDATA
    /// section of the resource, with some metadata for pointer resolution.
    ///
    /// To parse this section, use dns.ResourceData.fromOpaque
    opaque_rdata: ?dns.ResourceData.Opaque,

    const Self = @This();

    /// Extract an RDATA. This only spits out a slice of u8.
    /// Parsing of RDATA sections are in the dns.rdata module.
    ///
    /// Caller owns returned memory.
    fn readResourceDataFrom(
        reader: anytype,
        options: dns.ParserOptions,
    ) !?dns.ResourceData.Opaque {
        if (options.allocator) |allocator| {
            const rdata_length = try reader.readIntBig(u16);
            const rdata_index = reader.context.ctx.current_byte_count;

            var opaque_rdata = try allocator.alloc(u8, rdata_length);
            const read_bytes = try reader.read(opaque_rdata);
            std.debug.assert(read_bytes == opaque_rdata.len);
            return .{
                .data = opaque_rdata,
                .current_byte_count = rdata_index,
            };
        } else {
            return null;
        }
    }

    pub fn readFrom(reader: anytype, options: dns.ParserOptions) !Self {
        // TODO assert reader is WrapperReader
        logger.debug(
            "reading resource at {d} bytes",
            .{reader.context.ctx.current_byte_count},
        );
        var name = try Name.readFrom(reader, options);
        var typ = try ResourceType.readFrom(reader);
        var class = try ResourceClass.readFrom(reader);
        var ttl = try reader.readIntBig(i32);
        var opaque_rdata = try Self.readResourceDataFrom(reader, options);

        return Self{
            .name = name,
            .typ = typ,
            .class = class,
            .ttl = ttl,
            .opaque_rdata = opaque_rdata,
        };
    }

    pub fn writeTo(self: @This(), writer: anytype) !usize {
        const name_size = try self.name.?.writeTo(writer);
        const typ_size = try self.typ.writeTo(writer);
        const class_size = try self.class.writeTo(writer);
        const ttl_size = 32 / 8;
        try writer.writeIntBig(i32, self.ttl);

        const rdata_prefix_size = 16 / 8;
        try writer.writeIntBig(u16, @intCast(u16, self.opaque_rdata.?.data.len));
        const rdata_size = try writer.write(self.opaque_rdata.?.data);

        return name_size + typ_size + class_size + ttl_size +
            rdata_prefix_size + rdata_size;
    }
};

/// A DNS packet, as specified in RFC1035.
///
/// Beware, the amount of questions or resources given in this Packet
/// MUST be synchronized with the lengths set in the Header field.
///
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
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

    /// Write the network representation of this packet into a Writer.
    pub fn writeTo(self: Self, writer: anytype) !usize {
        std.debug.assert(self.header.question_length == self.questions.len);
        std.debug.assert(self.header.answer_length == self.answers.len);
        std.debug.assert(self.header.nameserver_length == self.nameservers.len);
        std.debug.assert(self.header.additional_length == self.additionals.len);

        const header_size = try self.header.writeTo(writer);

        var question_size: usize = 0;

        for (self.questions) |question| {
            const question_name_size = try question.name.?.writeTo(writer);
            const question_typ_size = try question.typ.writeTo(writer);
            const question_class_size = try question.class.writeTo(writer);

            question_size += question_name_size + question_typ_size + question_class_size;
        }

        const answers_size = try Self.writeResourceListTo(self.answers, writer);
        const nameservers_size = try Self.writeResourceListTo(self.nameservers, writer);
        const additionals_size = try Self.writeResourceListTo(self.additionals, writer);

        logger.debug(
            "header = {d}, question_size = {d}, answers_size = {d}," ++
                " nameservers_size = {d}, additionals_size = {d}",
            .{ header_size, question_size, answers_size, nameservers_size, additionals_size },
        );

        return header_size + question_size +
            answers_size + nameservers_size + additionals_size;
    }
};

/// Represents a Packet where all of its data was allocated dynamically.
pub const IncomingPacket = struct {
    allocator: std.mem.Allocator,
    packet: *Packet,

    fn freeResource(
        self: @This(),
        resource: Resource,
        options: DeinitOptions,
    ) void {
        if (options.names)
            if (resource.name) |name| name.deinit(self.allocator);
        if (resource.opaque_rdata) |opaque_rdata|
            self.allocator.free(opaque_rdata.data);
    }

    fn freeResourceList(
        self: @This(),
        resource_list: []Resource,
        options: DeinitOptions,
    ) void {
        for (resource_list) |resource| self.freeResource(resource, options);
        self.allocator.free(resource_list);
    }

    pub const DeinitOptions = struct {
        /// If the names inside the packet should be deinitialized or not.
        ///
        /// This should be set to false if you are passing ownership of the Name
        /// to dns.NamePool, as it has dns.NamePool.deinitWithNames().
        names: bool = true,
    };

    pub fn deinit(self: @This(), options: DeinitOptions) void {
        if (options.names) for (self.packet.questions) |question| {
            if (question.name) |name| name.deinit(self.allocator);
        };

        self.allocator.free(self.packet.questions);
        self.freeResourceList(self.packet.answers, options);
        self.freeResourceList(self.packet.nameservers, options);
        self.freeResourceList(self.packet.additionals, options);

        self.allocator.destroy(self.packet);
    }
};
