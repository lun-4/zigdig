const std = @import("std");
const assert = std.debug.assert;

const AddressType = union(enum) { Ipv4, Ipv6 };

const Errors = error{InvalidIP};

pub const AddressMeta = union(enum) {
    address: []const u8,
    hexAddress: []const u8,
    type: AddressType,

    const Self = @This();

    pub fn Ipv4() Self {
        return Self{
            .type = .Ipv4,
        };
    }

    /// Creates an IpAddress from a []const u8 address
    pub fn fromString(ip_address: []const u8) !Self {
        if (try valid(ip_address)) {
            return AddressMeta{ .address = .{ .address = ip_address } };
        }
    }

    /// Validates the calling ip address is actually valid
    pub fn valid(self: Self, ip_address: []const u8) !bool {
        switch (self.type) {
            .Ipv4 => {
                _ = try std.net.Ip4Address.parse(ip_address, 0);
            },
            .Ipv6 => {
                _ = try std.net.Ip6Address.parse(ip_address, 0);
            },
        }

        return true;
    }
};

// RFC reference for ARPA address formation: https://www.ietf.org/rfc/rfc2317.txt
pub const IpAddress = struct {
    address: AddressMeta,
    leastSignificationShiftValue: u16 = 0xFF, // Least significant bitmask value
    arpa_suffix: []const u8 = ".in-addr.arpa",

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, address: AddressMeta) !Self {
        return Self{
            .allocator = allocator,
            .address = address,
        };
    }

    /// Reverse IP address for Classless IN-ADDR.ARPA delegation
    pub fn reverseIpv4(self: Self) ![]const u8 {
        const ip = try std.net.Ip4Address.parse(self.address.address, 0);
        // ip.sa.addr is the raw addr u32 representation of the parsed address.
        var shifted_ip = self.bitmask(ip.sa.addr);

        // Just use native zig reverse
        std.mem.reverse(u32, &shifted_ip);

        // Note - If we buf print here, buffer will fill with nullbytes when we use dns.Name.fromString(buf, &alloc_locatio); So we alloc print here to avoid future complications
        return try std.fmt.allocPrint(self.allocator, "{d}.{d}.{d}.{d}{s}", .{ shifted_ip[0], shifted_ip[1], shifted_ip[2], shifted_ip[3], self.arpa_suffix });
    }

    // Not yet implemented
    pub fn reverseIpv6() !void {
        std.debug.print("Not implemented", .{});
        unreachable;
    }

    /// Converts from the little-endian hex values. Used for addresses stored on disk (Unix hosts) from sectors like /proc/net/tcp || /proc/net/udp
    pub fn hexConvertAddress(self: Self) ![4]u32 {
        return self.bitmask(try std.fmt.parseInt(u32, self.address.hexAddress, 16));
    }

    // Bit masking to ascertain least significant bit for parsing Ipv4 out of u32
    fn bitmask(self: Self, value: u32) [4]u32 {
        const b1 = (value & self.leastSignificationShiftValue);
        const b2 = (value >> 8) & self.leastSignificationShiftValue;
        const b3 = (value >> 16) & self.leastSignificationShiftValue;
        const b4 = (value >> 24) & self.leastSignificationShiftValue;

        return [4]u32{ b1, b2, b3, b4 };
    }
};

test "test bitmask and reverseral of ip address" {
    const ip = IpAddress{ .address = .{ .address = "8.8.4.4" }, .allocator = std.heap.page_allocator };
    const reversed = try ip.reverseIpv4();

    assert(std.mem.eql(u8, reversed, "4.4.8.8.in-addr.arpa"));
}

test "text hex conversion into IP address" {
    const hex_address: []const u8 = "0100007F"; // Converted to "0x0100007F for 127.0.0.1"

    const ip = IpAddress{ .address = .{ .hexAddress = hex_address }, .allocator = std.heap.page_allocator };
    const hex_converted = try ip.hexConvertAddress();

    var buf: [512]u8 = undefined;
    const c_val = try std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ hex_converted[0], hex_converted[1], hex_converted[2], hex_converted[3] });

    assert(std.mem.eql(u8, c_val, "127.0.0.1"));
}
