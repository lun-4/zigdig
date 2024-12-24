const std = @import("std");
const net = std.net;
const mem = std.mem;
const fmt = std.fmt;

pub const IpVersion = enum {
    v4,
    v6,
};

pub const CidrParseError = error{
    InvalidFormat,
    InvalidAddress,
    InvalidPrefixLength,
    AddressesExhausted,
};

pub const CidrRange = struct {
    version: IpVersion,
    first_address: [16]u8,
    prefix_len: u8,

    const Self = @This();

    /// Parse a CIDR notation string into a CidrRange
    pub fn parse(cidr: []const u8) !CidrRange {
        // Find the '/' separator
        const separator_pos = mem.indexOf(u8, cidr, "/") orelse return CidrParseError.InvalidFormat;

        // Split into address and prefix length
        const addr_str = cidr[0..separator_pos];
        const prefix_str = cidr[separator_pos + 1 ..];

        // Parse prefix length
        const prefix_len = fmt.parseInt(u8, prefix_str, 10) catch return CidrParseError.InvalidPrefixLength;

        // Try parsing as IPv4
        if (net.Address.parseIp4(addr_str, 0)) |ipv4| {
            if (prefix_len > 32) return CidrParseError.InvalidPrefixLength;

            var result = CidrRange{
                .version = .v4,
                .first_address = [_]u8{0} ** 16,
                .prefix_len = prefix_len,
            };

            // Convert IPv4 to mapped IPv6 format
            const bytes = std.mem.toBytes(ipv4.in.sa.addr);
            result.first_address[10] = 0xff;
            result.first_address[11] = 0xff;
            result.first_address[12] = bytes[0];
            result.first_address[13] = bytes[1];
            result.first_address[14] = bytes[2];
            result.first_address[15] = bytes[3];

            // Clear host portion
            const host_bits = 32 - prefix_len;
            if (prefix_len == 0) {
                // For /0, just set the entire address to 0
                std.mem.writeInt(u32, result.first_address[12..16], 0, .big);
            } else if (host_bits > 0) {
                const mask = ~(@as(u32, (@as(u32, 1) << @as(u5, @intCast(host_bits))) - 1));
                const addr = std.mem.readInt(u32, result.first_address[12..16], .big);
                const masked = addr & mask;
                std.mem.writeInt(u32, result.first_address[12..16], masked, .big);
            }

            return result;
        } else |_| {
            // Try parsing as IPv6
            if (net.Address.parseIp6(addr_str, 0)) |ipv6| {
                if (prefix_len > 128) return CidrParseError.InvalidPrefixLength;

                var result = CidrRange{
                    .version = .v6,
                    .first_address = ipv6.in6.sa.addr,
                    .prefix_len = prefix_len,
                };

                // Clear host portion
                const full_bytes = prefix_len / 8;
                const remaining_bits = prefix_len % 8;

                if (remaining_bits > 0) {
                    const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
                    result.first_address[full_bytes] &= mask;
                }

                for (result.first_address[full_bytes + @intFromBool(remaining_bits > 0) ..]) |*byte| {
                    byte.* = 0;
                }

                return result;
            } else |_| {
                return CidrParseError.InvalidAddress;
            }
        }
    }

    /// Get the last address in the CIDR range
    pub fn getLastAddress(self: Self) [16]u8 {
        var last = self.first_address;
        const full_bytes = self.prefix_len / 8;
        const remaining_bits = self.prefix_len % 8;

        if (remaining_bits > 0) {
            const mask = @as(u8, 0xFF) >> @intCast(remaining_bits);
            last[full_bytes] |= mask;
        }

        for (last[full_bytes + @intFromBool(remaining_bits > 0) ..]) |*byte| {
            byte.* = 0xFF;
        }

        return last;
    }

    /// Get the total number of addresses in the range
    pub fn getAddressCount(self: Self) u128 {
        const host_bits = switch (self.version) {
            .v4 => @as(u7, 32),
            .v6 => @as(u7, 128),
        } - self.prefix_len;

        return @as(u128, 1) << @intCast(host_bits);
    }

    /// Check if an IP address is within this CIDR range
    pub fn contains(self: Self, addr: []const u8) !bool {
        if (addr.len != 16) return CidrParseError.InvalidAddress;

        const full_bytes = self.prefix_len / 8;
        const remaining_bits = self.prefix_len % 8;

        // Compare full bytes
        if (!mem.eql(u8, addr[0..full_bytes], self.first_address[0..full_bytes])) {
            return false;
        }

        // Compare remaining bits if any
        if (remaining_bits > 0) {
            const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((addr[full_bytes] & mask) != (self.first_address[full_bytes] & mask)) {
                return false;
            }
        }

        return true;
    }

    /// Format the CIDR range as a string
    pub fn format(
        self: Self,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt_str;
        _ = options;

        switch (self.version) {
            .v4 => {
                // Format IPv4 address
                try writer.print("{}.{}.{}.{}/{}", .{
                    self.first_address[12],
                    self.first_address[13],
                    self.first_address[14],
                    self.first_address[15],
                    self.prefix_len,
                });
            },
            .v6 => {
                // Format IPv6 address
                const addr = self.first_address;
                var best_start: usize = 0;
                var best_len: usize = 0;
                var current_start: usize = 0;
                var current_len: usize = 0;

                // Find longest run of zeros for :: compression
                var i: usize = 0;
                while (i < 16) : (i += 2) {
                    if (addr[i] == 0 and addr[i + 1] == 0) {
                        if (current_len == 0) {
                            current_start = i;
                        }
                        current_len += 2;
                    } else {
                        if (current_len > best_len) {
                            best_start = current_start;
                            best_len = current_len;
                        }
                        current_len = 0;
                    }
                }
                if (current_len > best_len) {
                    best_start = current_start;
                    best_len = current_len;
                }

                // Write address with :: compression if applicable
                var pos: usize = 0;
                while (pos < 16) : (pos += 2) {
                    if (pos == best_start and best_len >= 4) {
                        try writer.writeAll(if (pos == 0) "::" else ":");
                        pos += best_len - 2;
                    } else {
                        if (pos != 0) try writer.writeAll(":");
                        const word = @as(u16, addr[pos]) << 8 | addr[pos + 1];
                        if (word != 0) {
                            try writer.print("{x}", .{word});
                        } else {
                            try writer.writeAll("0");
                        }
                    }
                }
                try writer.print("/{}", .{self.prefix_len});
            },
        }
    }
};

const testing = std.testing;

test "IPv4 basic parsing" {
    const cases = .{
        .{
            "192.168.1.0/24",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 0 },
            24,
            IpVersion.v4,
        },
        .{
            "10.0.0.0/8",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 0 },
            8,
            IpVersion.v4,
        },
        .{
            "172.16.0.0/12",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 172, 16, 0, 0 },
            12,
            IpVersion.v4,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "IPv6 basic parsing" {
    const cases = .{
        .{
            "2001:db8::/32",
            [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            32,
            IpVersion.v6,
        },
        .{
            "fe80::/10",
            [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            10,
            IpVersion.v6,
        },
        .{
            "::1/128",
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            128,
            IpVersion.v6,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "IPv6 compressed notation" {
    const cases = .{
        .{
            "2001:db8:0:0:0:0:0:0/32",
            "2001:db8::/32",
        },
        .{
            "2001:0db8:0000:0000:0000:0000:0000:0000/32",
            "2001:db8::/32",
        },
        .{
            "fe80:0:0:0:0:0:0:0/10",
            "fe80::/10",
        },
    };

    inline for (cases) |case| {
        const cidr1 = try CidrRange.parse(case[0]);
        const cidr2 = try CidrRange.parse(case[1]);
        try testing.expectEqual(cidr1.first_address, cidr2.first_address);
        try testing.expectEqual(cidr1.prefix_len, cidr2.prefix_len);
        try testing.expectEqual(cidr1.version, cidr2.version);
    }
}

test "Invalid CIDR formats" {
    const cases = .{
        "192.168.1.0", // Missing prefix
        "192.168.1.0/", // Empty prefix
        "192.168.1.0/33", // IPv4 prefix too large
        "2001:db8::/129", // IPv6 prefix too large
        "192.168.1.256/24", // Invalid IPv4 address
        "2001:db8::xyz/32", // Invalid IPv6 address
        "not.an.ip/24", // Invalid address format
        "/24", // Missing address
        "192.168.1.0/-1", // Negative prefix
        "192.168.1.0/a", // Non-numeric prefix
    };

    inline for (cases) |case| {
        if (CidrRange.parse(case)) |_| {
            try testing.expect(false); // Should not succeed
        } else |err| {
            switch (err) {
                error.InvalidFormat,
                error.InvalidAddress,
                error.InvalidPrefixLength,
                => {},
                else => try testing.expect(false),
            }
        }
    }
}

test "Edge cases" {
    const cases = .{
        .{
            "0.0.0.0/0", // Full IPv4 range
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 },
            0,
            IpVersion.v4,
        },
        .{
            "::/0", // Full IPv6 range
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            0,
            IpVersion.v6,
        },
        .{
            "255.255.255.255/32", // Single IPv4 address
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 255, 255, 255, 255 },
            32,
            IpVersion.v4,
        },
        .{
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", // Single IPv6 address
            [16]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            128,
            IpVersion.v6,
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
        try testing.expectEqual(case[2], cidr.prefix_len);
        try testing.expectEqual(case[3], cidr.version);
    }
}

test "Non-zero host bits" {
    const cases = .{
        .{
            "192.168.1.1/24", // Should clear to 192.168.1.0/24
            [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 0 },
        },
        .{
            "2001:db8::1/32", // Should clear to 2001:db8::/32
            [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        },
    };

    inline for (cases) |case| {
        const cidr = try CidrRange.parse(case[0]);
        try testing.expectEqual(case[1], cidr.first_address);
    }
}

test "Boundary prefix lengths" {
    const ipv4_cases = .{
        "192.168.1.0/0",
        "192.168.1.0/1",
        "192.168.1.0/31",
        "192.168.1.0/32",
    };

    const ipv6_cases = .{
        "2001:db8::/0",
        "2001:db8::/1",
        "2001:db8::/127",
        "2001:db8::/128",
    };

    inline for (ipv4_cases) |case| {
        const cidr = try CidrRange.parse(case);
        try testing.expect(cidr.version == .v4);
    }

    inline for (ipv6_cases) |case| {
        const cidr = try CidrRange.parse(case);
        try testing.expect(cidr.version == .v6);
    }
}
