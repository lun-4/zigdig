const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.dns_name);

pub const LabelComponent = union(enum) {
    Full: []const u8,
    /// Holds the first offset component of that pointer.
    ///
    /// You still have to read a byte for the second component and assemble
    /// it into the final packet offset.
    Pointer: u16,
    Null: void,
};

pub const RawName = struct {
    labels: []LabelComponent,
};

const ReadNameOptions = struct {
    max_label_count: usize = 128,
    is_rdata: bool = false,
};

pub const Name = union(enum) {
    raw: RawName,
    full: FullName,

    const Self = @This();

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .raw => |raw| {
                for (raw.labels) |label| switch (label) {
                    .Full => |data| allocator.free(data),
                    else => {},
                };

                allocator.free(raw.labels);
            },
            .full => |full| {
                for (full.labels) |label| allocator.free(label);
                allocator.free(full.labels);
            },
        }
    }

    /// Caller owns returned memory.
    pub fn readFrom(
        reader: anytype,
        options: dns.ParserOptions,
    ) !?Self {
        const current_byte_index = reader.context.ctx.current_byte_count;

        if (options.allocator) |allocator| {
            var components = std.ArrayList(LabelComponent).init(allocator);
            defer components.deinit();

            var is_raw: bool = false;

            while (true) {
                if (components.items.len > options.max_label_size)
                    return error.Overflow;

                const component = (try Self.readLabelComponent(reader, allocator)).?;
                logger.debug("read name: component {}", .{component});
                try components.append(component);
                switch (component) {
                    .Null => break,
                    .Pointer => {
                        is_raw = true;
                        break;
                    },
                    else => {},
                }
            }

            return if (is_raw) .{ .raw = .{
                .labels = try components.toOwnedSlice(),
            } } else .{
                .full = try FullName.fromAssumedComponents(
                    allocator,
                    try components.toOwnedSlice(),
                    current_byte_index,
                ),
            };
        } else {
            // skip the name in the reader
            var name_index: usize = 0;

            while (true) {
                if (name_index > options.max_label_size)
                    return error.Overflow;

                var maybe_component = try Self.readLabelComponent(reader, null);
                if (maybe_component) |component| switch (component) {
                    .Null, .Pointer => break,
                    else => {},
                };
            }

            return null;
        }
    }

    /// Deserialize a LabelComponent, which can be:
    ///  - a pointer
    ///  - a full label ([]const u8)
    ///  - a null octet
    fn readLabelComponent(
        reader: anytype,
        maybe_allocator: ?std.mem.Allocator,
    ) !?LabelComponent {
        // pointers, in the binary representation of a byte, are as follows
        //  1 1 B B B B B B | B B B B B B B B
        // they are two bytes length, but to identify one, you check if the
        // first two bits are 1 and 1 respectively.
        //
        // then you read the rest, and turn it into an offset (without the
        // starting bits!!!)
        //
        // to prevent inefficiencies, we just read a single byte, see if it
        // has the starting bits, and then we chop it off, merging with the
        // next byte. pointer offsets are 14 bits long
        //
        // when it isn't a pointer, its a length for a given label, and that
        // length can only be a single byte.
        //
        // if the length is 0, its a null octet
        logger.debug(
            "reading label component at {d} bytes",
            .{reader.context.ctx.current_byte_count},
        );
        var possible_length = try reader.readIntBig(u8);
        if (possible_length == 0) return LabelComponent{ .Null = {} };

        // RFC1035:
        // since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.

        var bit1 = (possible_length & (1 << 7)) != 0;
        var bit2 = (possible_length & (1 << 6)) != 0;

        if (bit1 and bit2) {
            const second_offset_component = try reader.readIntBig(u8);

            // merge them together
            var offset: u16 = (possible_length << 7) | second_offset_component;

            // set first two bits of ptr_offset to zero as they're the
            // pointer prefix bits (which are always 1, which brings problems)
            offset &= ~@as(u16, 1 << 15);
            offset &= ~@as(u16, 1 << 14);

            return LabelComponent{ .Pointer = offset };
        } else {
            // those must be 0 for a correct label length to be made
            std.debug.assert((!bit1) and (!bit2));

            // the next <possible_length> bytes contain a full label.
            if (maybe_allocator) |allocator| {
                var label = try allocator.alloc(u8, possible_length);
                const read_bytes = try reader.read(label);
                if (read_bytes != label.len) logger.err(
                    "possible_length = {d} read_bytes = {d} label.len = {d}",
                    .{ possible_length, read_bytes, label.len },
                );
                std.debug.assert(read_bytes == label.len);
                return LabelComponent{ .Full = label };
            } else {
                logger.debug("read_name: skip {d} bytes as no alloc", .{possible_length});
                try reader.skipBytes(possible_length, .{});
                return null;
            }
        }
    }

    pub fn writeTo(self: Self, writer: anytype) !usize {
        return switch (self) {
            .raw => unreachable, // must resolve against original packet so that we know the full name
            .full => |full| try full.writeTo(writer),
        };
    }
    pub fn networkSize(self: Self) usize {
        return switch (self) {
            .raw => unreachable, // must resolve against original packet so that we know the full name
            .full => |full| full.networkSize(),
        };
    }

    pub fn fromString(domain: []const u8, buffer: [][]const u8) !Self {
        return .{ .full = try FullName.fromString(domain, buffer) };
    }
};

/// Represents a single DNS domain-name, which is a slice of strings.
///
/// The "www.google.com" friendly domain name can be represented in DNS as a
/// sequence of labels: first "www", then "google", then "com", with a length
/// prefix for all of them, ending in a null byte.
///
/// Keep in mind Name's are not singularly deserializeable, as the names
/// could be pointers to different bytes in the packet.
/// (RFC1035, section 4.1.4 Message Compression)
pub const FullName = struct {
    /// The name's labels.
    labels: [][]const u8,

    /// Represents the index of that name in its packet's body.
    ///
    /// **This is an internal field for DNS name pointer resolution.**
    packet_index: ?usize = null,

    const Self = @This();

    pub fn fromAssumedComponents(
        allocator: std.mem.Allocator,
        components: []LabelComponent,
        packet_index: ?usize,
    ) !Self {
        var labels = std.ArrayList([]const u8).init(allocator);
        defer labels.deinit();

        for (components) |component| switch (component) {
            .Full => |data| try labels.append(data),
            .Pointer => unreachable,
            .Null => break,
        };

        return Self{
            .labels = try labels.toOwnedSlice(),
            .packet_index = packet_index,
        };
    }

    /// Only use this if you have manually heap allocated a Name
    /// through the internal Packet.readName function.
    ///
    /// IncomingPacket.deinit already frees alloccated Names.
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        for (self.labels) |label| allocator.free(label);
        allocator.free(self.labels);
    }

    /// Returns the total size in bytes of the DNS Name
    pub fn networkSize(self: Self) usize {
        // by default, add the null octet at the end of it
        var total_size: usize = 1;

        for (self.labels) |label| {
            // length octet + the actual label octets
            total_size += @sizeOf(u8);
            total_size += label.len * @sizeOf(u8);
        }

        return total_size;
    }

    /// Get a Name out of a domain name ("www.google.com", for example).
    pub fn fromString(domain: []const u8, buffer: [][]const u8) !Self {
        if (domain.len > 255) return error.Overflow;

        var it = std.mem.split(u8, domain, ".");
        var idx: usize = 0;
        while (it.next()) |label| {
            // Is there a better error for this?
            if (idx > (buffer.len - 1)) return error.Underflow; // buffer too small

            buffer[idx] = label;
            idx += 1;
        }

        return Self{ .labels = buffer[0..idx] };
    }

    pub fn writeTo(self: Self, writer: anytype) !usize {
        var size: usize = 0;
        for (self.labels) |label| {
            std.debug.assert(label.len < 255);

            try writer.writeIntBig(u8, @intCast(u8, label.len));
            size += 1;

            for (label) |byte| {
                try writer.writeByte(byte);
                size += 1;
            }
        }

        // null-octet for the end of labels for this name
        try writer.writeByte(@as(u8, 0));
        return size + 1;
    }

    /// Format the given DNS name.
    pub fn format(
        self: Self,
        comptime f: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = f;
        _ = options;

        for (self.labels) |label| {
            try std.fmt.format(writer, "{s}.", .{label});
        }
    }
};
