const std = @import("std");
const address = @import("./address.zig");
const dns = @import("./lib.zig");
const assert = std.debug.assert;

/// ReverseLookup is the primary interface for classless IN-ADDR.ARPA (IPv4) and IP6.ARPA (IPv6) delegations
pub const ReverseLookup = struct {
    allocator: std.mem.Allocator,
    ip_address: []const u8,
    packet_id: u16, // Arbitrary packet ID

    const Self = @This();
    const max_ipv6_label_size = 35;
    const max_ipv4_label_size = 6;

    pub fn init(allocator: std.mem.Allocator, ip_address: []const u8, packet_id: u16) !Self {
        return Self{
            .allocator = allocator,
            .ip_address = ip_address,
            .packet_id = packet_id,
        };
    }

    /// Reverse lookup on a given ipv4 ip address
    pub fn lookupIpv4(self: Self) ![][]const u8 {
        var add = try address.IpAddress.init(self.allocator, try address.AddressMeta.Ipv4().fromString(self.ip_address));
        const arpa_address = try add.reverseIpv4();

        var labels: [max_ipv4_label_size][]const u8 = undefined;
        const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

        return try self.buildAndSendPacket(apra_address_dns_name);
    }

    /// Reverse lookup on a given ipv6 ip address
    pub fn lookupIpv6(self: Self) ![][]const u8 {
        var add = try address.IpAddress.init(self.allocator, try address.AddressMeta.Ipv6().fromString(self.ip_address));
        const arpa_address = try add.reverseIpv6();

        var labels: [max_ipv6_label_size][]const u8 = undefined;
        const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

        return try self.buildAndSendPacket(apra_address_dns_name);
    }

    /// Internal function to build and send the DNS packet for reverse lookup agnostic of IP address type (ipv4 | ipv6)
    fn buildAndSendPacket(self: Self, apra_address_dns_name: dns.Name) ![][]const u8 {
        var name_pool = dns.NamePool.init(self.allocator);
        defer name_pool.deinitWithNames();

        var question = [_]dns.Question{.{
            .class = .IN,
            .typ = .PTR,
            .name = apra_address_dns_name,
        }};

        var empty = [_]dns.Resource{};

        const packet = dns.Packet{
            .header = .{
                .id = self.packet_id,
                .wanted_recursion = true, // Need recursion of at least 1 depth for reverse lookup
                .answer_length = 0, // 0 for reverse query
                .question_length = 1,
                .nameserver_length = 0,
                .additional_length = 0,
                .opcode = .Query,
            },
            .questions = &question,
            .answers = &empty,
            .nameservers = &empty,
            .additionals = &[_]dns.Resource{},
        };

        const conn = try dns.helpers.connectToSystemResolver();
        defer conn.close();
        try conn.sendPacket(packet);

        const reply = try conn.receiveFullPacket(
            self.allocator,
            4096,
            .{ .name_pool = &name_pool },
        );
        defer reply.deinit(.{ .names = false });

        const reply_packet = reply.packet;

        // Parse reply packet, if there are answers return them in a serialized fashion for human consumption. Else empty
        if (reply_packet.answers.len > 0) {
            var dns_names = try self.allocator.alloc([]u8, reply_packet.answers.len);
            var index: usize = 0;
            for (reply_packet.answers) |resource| {
                const resource_data = try dns.ResourceData.fromOpaque(
                    resource.typ,
                    resource.opaque_rdata.?,
                    .{
                        .name_provider = .{ .full = &name_pool },
                        .allocator = name_pool.allocator,
                    },
                );

                //fromOpaque read the data, so if we utilize any standard reader/writer we have access to the []const u8 opaque data value. So we just allocprint here
                const dns_name = try std.fmt.allocPrint(self.allocator, "{s}", .{resource_data});

                dns_names[index] = dns_name;
                index += 1;
            }

            return dns_names;
        } else {
            return &[_][]const u8{}; // empty
        }
    }
};

test "reverse lookup of Ipv4 address" {
    const name = "dns.google.";
    const test_address = "8.8.4.4";
    var reverse = try ReverseLookup.init(std.heap.page_allocator, test_address, 123);
    const names = try reverse.lookupIpv4();

    assert(names.len > 0);
    assert(std.mem.eql(u8, names[0], name));

    // Test when no name matches
    const non_address = "123.123.123.123";
    reverse = try ReverseLookup.init(std.heap.page_allocator, non_address, 123);
    const names_non = try reverse.lookupIpv4();

    // This should be empty
    assert(names_non.len == 0);
}

test "reverse lookup of ipv6" {
    // Test existing Ipv6 address (google dns - same as 8.8.4.4)
    const google_ipv6_address = "2001:4860:4860::8888";
    const name = "dns.google.";
    var reverse = try ReverseLookup.init(std.heap.page_allocator, google_ipv6_address, 123);
    const names = try reverse.lookupIpv6();

    assert(names.len > 0);
    assert(std.mem.eql(u8, names[0], name));

    // Test when no name matches (localhost ipv6)
    const non_existent_ipv6 = "2001:4860:4860::1234";
    reverse = try ReverseLookup.init(std.heap.page_allocator, non_existent_ipv6, 124);
    const names_non = try reverse.lookupIpv6();

    // This should be empty
    assert(names_non.len == 0);
}
