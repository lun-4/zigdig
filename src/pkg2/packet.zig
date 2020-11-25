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

    /// TODO
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
};
