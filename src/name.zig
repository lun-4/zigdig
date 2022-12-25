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

    const Self = @This();

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
