const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.dns_name);

/// Represents a raw component of a DNS label.
pub const LabelComponent = union(enum) {
    Full: []const u8,
    /// Holds the first offset component of that pointer.
    ///
    /// You still have to read a byte for the second component and assemble
    /// it into the final packet offset.
    Pointer: u16,
    Null: void,
};

/// A raw name that may end in a Pointer LabelComponent.
pub const RawName = struct {
    components: []LabelComponent,

    /// Represents the index of that name in its packet's body.
    ///
    /// **This is an internal field for DNS name pointer resolution.**
    packet_index: ?usize = null,
};

/// Wrapper class for safer handling of names
pub const Name = union(enum) {
    raw: RawName,
    full: FullName,

    const Self = @This();

    /// Deinitializes the entire name, including the labels inside, given
    /// an allocator.
    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        switch (self) {
            .raw => |raw| {
                for (raw.components) |label| switch (label) {
                    .Full => |data| allocator.free(data),
                    else => {},
                };

                allocator.free(raw.components);
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

            var has_pointer: bool = false;

            while (true) {
                if (components.items.len > options.max_label_size)
                    return error.Overflow;

                const component = (try Self.readLabelComponent(reader, allocator)).?;
                logger.debug("read name: component {}", .{component});
                try components.append(component);
                switch (component) {
                    .Null => break,
                    .Pointer => {
                        has_pointer = true;
                        break;
                    },
                    else => {},
                }
            }

            return if (has_pointer) .{ .raw = .{
                .components = try components.toOwnedSlice(),
                .packet_index = current_byte_index,
            } } else .{
                .full = try FullName.fromAssumedComponents(
                    allocator,
                    components.items,
                    current_byte_index,
                ),
            };
        } else {
            // skip the name in the reader
            var name_index: usize = 0;

            while (true) : (name_index += 1) {
                if (name_index > options.max_label_size)
                    return error.Overflow;

                const maybe_component = try Self.readLabelComponent(reader, null);
                if (maybe_component) |component| switch (component) {
                    .Null, .Pointer => break,
                    else => {},
                };
            }

            return null;
        }
    }

    /// Deserialize a single LabelComponent, which can be:
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
        const possible_length = try reader.readInt(u8, .big);
        if (possible_length == 0) return LabelComponent{ .Null = {} };

        // RFC1035:
        // since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.

        const bit1 = (possible_length & (1 << 7)) != 0;
        const bit2 = (possible_length & (1 << 6)) != 0;

        if (bit1 and bit2) {
            const second_offset_component = try reader.readInt(u8, .big);

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
                const label = try allocator.alloc(u8, possible_length);
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

    /// Write the network representation of a name onto a stream.
    pub fn writeTo(self: Self, writer: anytype) !usize {
        return switch (self) {
            // NOTE we don't serialize to pointers.
            .raw => unreachable, // must convert to full name to be able to write
            .full => |full| try full.writeTo(writer),
        };
    }

    /// Return the byte size of the network representation of the name.
    pub fn networkSize(self: Self) usize {
        return switch (self) {
            .raw => unreachable, // must resolve against original packet so that we know the full name
            .full => |full| full.networkSize(),
        };
    }

    /// Create a FullName with a given buffer that will hold its labels.
    pub fn fromString(domain: []const u8, buffer: [][]const u8) !Self {
        return .{ .full = try FullName.fromString(domain, buffer) };
    }

    pub fn format(
        self: Self,
        comptime f: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return switch (self) {
            .full => |full| full.format(f, options, writer),
            .raw => |raw| for (raw.components) |component| switch (component) {
                .Pointer => |ptr| try std.fmt.format(writer, "(pointer={d}).", .{ptr}),
                .Full => |label| try std.fmt.format(writer, "{s}.", .{label}),
                .Null => break,
            },
        };
    }
};

/// Represents a single DNS domain name, which is a slice of strings.
///
/// The "www.google.com" friendly domain name can be represented in DNS as a
/// sequence of labels: first "www", then "google", then "com", with a length
/// prefix for all of them, ending in a null byte.
///
/// For RawName, the names may end in a pointer that is dependent on the overall
/// parsing context of the packet. To be able to turn a RawName into a FullName,
/// look at NamePool.transmuteName
pub const FullName = struct {
    /// The name's labels.
    labels: [][]const u8,

    /// Represents the index of that name in its packet's body.
    ///
    /// **This is an internal field for DNS name pointer resolution.**
    packet_index: ?usize = null,

    const Self = @This();

    /// Create a FullName from a []LabelComponent.
    ///
    /// Assumes that the slice does not end in a pointer.
    ///
    /// Does not take ownership of the returned slice.
    /// Caller owns returned memory.
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
    /// IncomingPacket.deinit already frees allocated Names.
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
    pub fn fromString(domain: []const u8, buffer: [][]const u8) error{
        /// The given domain contains an empty label (e.g "google...com")
        ///
        /// Empty labels are disallowed in DNS, as "length 0" label is also
        /// determined as the Null label, which ends a name.
        EmptyLabelInName,
        /// The given DNS name has too many labels for the given buffer to hold.
        Overflow,
    }!Self {
        if (domain.len > 255) return error.Overflow;

        var it = std.mem.split(u8, domain, ".");
        var idx: usize = 0;
        while (it.next()) |label| {
            if (label.len == 0) return error.EmptyLabelInName;
            if (idx > (buffer.len - 1)) return error.Overflow;

            buffer[idx] = label;
            idx += 1;
        }

        return Self{ .labels = buffer[0..idx] };
    }

    pub fn writeTo(self: Self, writer: anytype) !usize {
        var size: usize = 0;
        for (self.labels) |label| {
            std.debug.assert(label.len < 255);

            try writer.writeInt(u8, @as(u8, @intCast(label.len)), .big);
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

const NameList = std.ArrayList(dns.Name);

/// Implements RFC1035, section 4.1.4 Message Compression.
///
/// This is an entity that holds Name entities inside, with their respective
/// locations inside the packet. With that information, it is able to convert
/// from a RawName given by deserialization into a FullName that contains
/// all wanted labels.
pub const NamePool = struct {
    allocator: std.mem.Allocator,
    held_names: NameList,

    const Self = @This();
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .held_names = NameList.init(allocator),
        };
    }

    pub fn deinit(self: Self) void {
        self.held_names.deinit();
    }

    pub fn deinitWithNames(self: Self) void {
        for (self.held_names.items) |name| name.deinit(self.allocator);
        self.deinit();
    }

    /// Convert dns.RawName or FullName to FullName, applying pointer
    /// resolution, and storing the name for future pointers to be resolved.
    ///
    /// takes ownership of the given name's memory.
    pub fn transmuteName(self: *Self, name: dns.Name) !dns.Name {
        return switch (name) {
            .full => blk: {
                try self.held_names.append(name);
                break :blk name;
            },
            .raw => |raw| blk: {
                defer name.deinit(self.allocator);
                // this ends in a Pointer, create a new FullName
                var resolved_labels = std.ArrayList([]const u8).init(self.allocator);
                defer resolved_labels.deinit();

                for (raw.components) |raw_component| switch (raw_component) {
                    .Full => |text| try resolved_labels.append(try self.allocator.dupe(u8, text)),
                    .Pointer => |packet_offset| {

                        // step 1: find out the name we already have
                        // that contains this pointer
                        var maybe_referenced_name: ?dns.FullName = null;
                        for (self.held_names.items) |held_name_from_list| {
                            const held_name = held_name_from_list.full;

                            const packet_index =
                                if (held_name.packet_index) |idx|
                                idx
                            else
                                continue;

                            // calculate end packet offset using length of the
                            // full name.

                            const start_index = packet_index;
                            var name_length: usize = 0;
                            for (held_name.labels) |label|
                                name_length += label.len;
                            const end_index = packet_index + name_length;

                            if (start_index <= packet_offset and packet_offset <= end_index) {
                                maybe_referenced_name = held_name;
                            }
                        }

                        if (maybe_referenced_name) |referenced_name| {
                            var label_cursor: usize = referenced_name.packet_index.?;
                            var label_index: ?usize = null;

                            for (referenced_name.labels, 0..) |label, idx| {
                                // if cursor is in offset's range, select that
                                // label onwards as our new label
                                const label_start = label_cursor;
                                if (label_start <= packet_offset) {
                                    label_index = idx;
                                }
                                label_cursor += label.len;
                            }

                            const referenced_labels = referenced_name.labels[label_index.?..];

                            for (referenced_labels) |referenced_label| {
                                try resolved_labels.append(try self.allocator.dupe(u8, referenced_label));
                            }
                        } else {
                            logger.warn(
                                "unknown pointer offset: pointer has offset={d}",
                                .{packet_offset},
                            );

                            for (self.held_names.items) |held_name| {
                                logger.warn(
                                    "known name: {} at offset {?d}",
                                    .{ held_name, held_name.full.packet_index },
                                );
                            }

                            return error.UnknownPointerOffset;
                        }
                    },
                    .Null => unreachable,
                };

                const full_name = dns.Name{ .full = dns.FullName{
                    .labels = try resolved_labels.toOwnedSlice(),
                    .packet_index = name.raw.packet_index,
                } };
                try self.held_names.append(full_name);
                break :blk full_name;
            },
        };
    }

    /// given a dns.Question or dns.Resource, resolve pointers and return
    /// that same Question or Resource with a FullName inside of it.
    ///
    /// to be able to do this, ALL questions and resources must be registered
    /// in the NamePool.
    ///
    /// this takes ownership of the given resource, returning a new one with
    /// FullName set in the respective "name" union field.
    pub fn transmuteResource(self: *Self, resource: anytype) !@TypeOf(resource) {
        switch (@TypeOf(resource)) {
            dns.Question => {
                var new_question = resource;
                new_question.name = try self.transmuteName(resource.name.?);
                return new_question;
            },
            dns.Resource => {
                var new_resource = resource;
                new_resource.name = try self.transmuteName(resource.name.?);
                return new_resource;
            },
            else => @compileError("invalid type to resolve in name pool " ++ @typeName(@TypeOf(resource))),
        }
    }
};
