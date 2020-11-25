const std = @import("std");

/// Represents a single DNS domain-name, which is a slice of strings.
///
/// The "www.google.com" friendly domain name can be represented in DNS as a
/// sequence of labels: first "www", then "google", then "com", with a length
/// prefix for all of them, ending in a null byte.
///
/// Keep in mind Name's are not singularly deserializeable, as the names
/// could be pointers to different bytes in the packet.
/// (RFC1035, section 4.1.4 Message Compression)
pub const Name = struct {
    /// The name's labels.
    labels: [][]const u8,

    /// Returns the total size in bytes of the DNS Name
    pub fn size(self: @This()) usize {
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
    pub fn fromString(domain: []const u8, buffer: [][]const u8) !@This() {
        if (domain.len > 255) return error.Overflow;

        var it = std.mem.split(domain, ".");
        var idx: usize = 0;
        while (it.next()) |label| {
            buffer[idx] = label;
            idx += 1;
        }

        return @This(){ .labels = buffer[0..idx] };
    }

    pub fn serialize(self: @This(), serializer: anytype) !void {
        for (self.labels) |label| {
            std.debug.assert(label.len < 255);
            try serializer.serialize(@intCast(u8, label.len));
            for (label) |byte| {
                try serializer.serialize(byte);
            }
        }

        // null-octet for the end of labels for this name
        try serializer.serialize(@as(u8, 0));
    }

    /// Format the given DNS name.
    pub fn format(self: @This(), comptime f: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        if (f.len != 0) {
            @compileError("Unknown format character: '" ++ f ++ "'");
        }

        for (self.labels) |label| {
            try fmt.format(writer, "{}.", .{label});
        }
    }
};
