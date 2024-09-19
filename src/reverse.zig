const std = @import("std");
const address = @import("./address.zig");
const dns = @import("./lib.zig");
const assert = std.debug.assert;

const ReverseLookup = struct {
    allocator: std.mem.Allocator,
    ip_address: []const u8,
    packet_id: u16, // Arbitrary packet ID

    const Self = @This();

    fn init(allocator: std.mem.Allocator, ip_address: []const u8, packet_id: u16) !Self {
        return Self{
            .allocator = allocator,
            .ip_address = ip_address,
            .packet_id = packet_id,
        };
    }

    /// Reverse lookup on a given ipv4 ip address
    /// Returns an array of N Dns Names resolved from reverse lookup
    fn lookupIpv4(self: Self) ![][]const u8 {
        var add = try address.IpAddress.init(self.allocator, try address.AddressMeta.Ipv4().fromString(self.ip_address));
        const arpa_address = try add.reverseIpv4();

        var labels: [6][]const u8 = undefined;
        const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

        return try self.buildAndSendPacket(apra_address_dns_name);
    }

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
            4096, // Larger for ipv6?
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

    /// Reverse lookup on a given ipv6 ip address
    fn lookupIpv6(self: Self) ![][]const u8 {
        var add = try address.IpAddress.init(self.allocator, try address.AddressMeta.Ipv6().fromString(self.ip_address));
        const arpa_address = try add.reverseIpv6();

        var labels: [35][]const u8 = undefined;
        const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

        return try self.buildAndSendPacket(apra_address_dns_name);
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

// All of this is done in Reverse struct. The raw test sector is purely for testing and development :)
// We can wireshark/tcpdump capture the UDP packet request for dns resolution of the reverse address for debugging
// dig command for generating packets for review/reference - dig -x 8.8.4.4 +noadditional +nostats +nocomments +answer +noedns +noadflag
// sudo tcpdump -i any udp port 53 (capture udp traffic for DNS queries) (wireshark works even better to parse the packets)
// wireshark (udp.port == 53) in filter bar and capture on lo interface
test "reverse address lookup raw" {
    const id = 4100; // Arbitrary int
    const name = "dns.google.";
    const ip_address = "8.8.4.4";

    const allocator: std.mem.Allocator = std.heap.page_allocator;
    // Reversed arpa compatible address for Classless IN-ADDR.ARPA delegation
    var address_local = dns.IpAddress{ .address = .{ .address = ip_address }, .allocator = allocator };
    const arpa_address = try address_local.reverseIpv4();

    var labels: [6][]const u8 = undefined;
    const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

    var name_pool = dns.NamePool.init(allocator);
    defer name_pool.deinitWithNames();

    var question = [_]dns.Question{.{
        .class = .IN,
        .typ = .PTR,
        .name = apra_address_dns_name,
    }};

    var empty = [_]dns.Resource{};

    const packet = dns.Packet{
        .header = .{
            .id = id,
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

    // For debugging remove comments
    // const stdout = std.io.getStdOut();
    // try dns.helpers.printAsZoneFile(&packet, undefined, stdout.writer());

    const reply = try conn.receiveFullPacket(
        allocator,
        4096, // Max PRT query DNS packets are usually 104 bytes. This could be much smaller
        .{ .name_pool = &name_pool },
    );
    defer reply.deinit(.{ .names = false });

    // For debugging remove comments
    const reply_packet = reply.packet;
    // try dns.helpers.printAsZoneFile(reply_packet, &name_pool, stdout.writer());

    // Capture all responses
    var dns_names = try allocator.alloc([]u8, reply_packet.answers.len);
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
        const dns_name = try std.fmt.allocPrint(allocator, "{s}", .{resource_data});

        dns_names[index] = dns_name;
        index += 1;
    }

    assert(std.mem.eql(u8, dns_names[0], name));
    assert(dns_names.len > 0);
}

test "reverse lookup of ipv6" {
    const google_ipv6_address = "2001:4860:4860::8888";
    // const non_existent_ipv6 = "2001:4860:4860::1234";
    const name = "dns.google.";
    var reverse = try ReverseLookup.init(std.heap.page_allocator, google_ipv6_address, 123);
    const names = try reverse.lookupIpv6();

    assert(names.len > 0);
    assert(std.mem.eql(u8, names[0], name));

    // // Test when no name matches (localhost ipv6)
    // reverse = try ReverseLookup.init(std.heap.page_allocator, non_existent_ipv6, 123);
    // const names_non = try reverse.lookupIpv6();

    // // This should be empty
    // assert(names_non.len == 0);
}
