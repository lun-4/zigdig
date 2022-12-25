const std = @import("std");

/// Represents a DNS type.
/// Keep in mind this enum does not declare all possible DNS types.
pub const ResourceType = enum(u16) {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,

    AAAA = 28,
    // TODO LOC = 29, (check if it's worth it. https://tools.ietf.org/html/rfc1876)
    SRV = 33,

    // those types are only valid in request packets. they may be wanted
    // later on for completeness, but for now, it's more hassle than it's worth.
    // AXFR = 252,
    // MAILB = 253,
    // MAILA = 254,
    // ANY = 255,

    // should this enum be non-exhaustive?
    // trying to get it non-exhaustive gives "TODO @tagName on non-exhaustive enum https://github.com/ziglang/zig/issues/3991"
    //_,

    /// Try to convert a given string (case-insensitive compare) to an
    /// integer representing a Type.
    pub fn fromString(str: []const u8) error{InvalidResourceType}!@This() {
        // this returned Overflow but i think InvalidResourceType is also valid
        // considering we dont have resource types that are more than 10
        // characters long.
        if (str.len > 10) return error.InvalidResourceType;

        // TODO we wouldn't need this buffer if we could do some
        // case insensitive string comparison in stdlib or something
        var buffer: [10]u8 = undefined;
        for (str) |char, index| {
            buffer[index] = std.ascii.toUpper(char);
        }

        const uppercased = buffer[0..str.len];

        const type_info = @typeInfo(@This()).Enum;
        inline for (type_info.fields) |field| {
            if (std.mem.eql(u8, uppercased, field.name)) {
                return @intToEnum(@This(), field.value);
            }
        }

        return error.InvalidResourceType;
    }

    pub fn writeTo(self: @This(), writer: anytype) !usize {
        try writer.writeIntBig(u16, @enumToInt(self));
        return 16 / 8;
    }
};

/// Represents a DNS class.
/// (TODO point to rfc)
pub const ResourceClass = enum(u16) {
    /// The internet
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    WILDCARD = 255,

    pub fn writeTo(self: @This(), writer: anytype) !usize {
        try writer.writeIntBig(u16, @enumToInt(self));
        return 16 / 8;
    }
};
