const std = @import("std");

const logger = std.log.scoped(.dns_enums);

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

    // https://www.rfc-editor.org/rfc/rfc6891#section-6
    //    The OPT RR has RR type 41.
    OPT = 41,

    // those types are only valid in request packets. they may be wanted
    // later on for completeness, but for now, it's more hassle than it's worth.
    // AXFR = 252,
    // MAILB = 253,
    // MAILA = 254,
    // ANY = 255,

    // should this enum be non-exhaustive?
    // what does it actually mean to be non-exhaustive?
    //_,

    const Self = @This();

    /// Try to convert a given string (case-insensitive compare) to an
    /// integer representing a Type.
    pub fn fromString(str: []const u8) error{InvalidResourceType}!Self {
        // this returned Overflow but i think InvalidResourceType is also valid
        // considering we dont have resource types that are more than 10
        // characters long.
        if (str.len > 10) return error.InvalidResourceType;

        // TODO we wouldn't need this buffer if we could do some
        // case insensitive string comparison in stdlib or something
        var buffer: [10]u8 = undefined;
        for (str, 0..) |char, index| {
            buffer[index] = std.ascii.toUpper(char);
        }

        const uppercased = buffer[0..str.len];

        const type_info = @typeInfo(Self).Enum;
        inline for (type_info.fields) |field| {
            if (std.mem.eql(u8, uppercased, field.name)) {
                return @as(Self, @enumFromInt(field.value));
            }
        }

        return error.InvalidResourceType;
    }

    pub fn readFrom(reader: anytype) !Self {
        const resource_type_int = try reader.readInt(u16, .big);
        return std.meta.intToEnum(Self, resource_type_int) catch |err| {
            logger.err(
                "unknown resource type {d}, got {s}",
                .{ resource_type_int, @errorName(err) },
            );
            return err;
        };
    }

    /// Write the network representation of this type to a stream.
    ///
    /// Returns amount of bytes written.
    pub fn writeTo(self: Self, writer: anytype) !usize {
        try writer.writeInt(u16, @intFromEnum(self), .big);
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

    pub fn readFrom(reader: anytype) !@This() {
        const resource_class_int = try reader.readInt(u16, .big);
        return std.meta.intToEnum(@This(), resource_class_int) catch |err| {
            logger.err(
                "unknown resource class {d}, got {s}",
                .{ resource_class_int, @errorName(err) },
            );
            return err;
        };
    }

    /// Write the network representation of this class to a stream.
    ///
    /// Returns amount of bytes written.
    pub fn writeTo(self: @This(), writer: anytype) !usize {
        try writer.writeInt(u16, @intFromEnum(self), .big);
        return 16 / 8;
    }
};
