const std = @import("std");
const address = @import("./address.zig");
const dns = @import("./lib.zig");
const assert = std.debug.assert;

const ReverseLookup = struct {
    allocator: std.mem.allocator,
    ip_address: []const u8,
    packet_id: u16, // Arbitrary packet ID

    const Self = @This();

    fn init(allocator: std.mem.Allocator, ip_address: address.AddressMeta, packet_id: u16) !Self {
        return Self{
            .allocator = allocator,
            .ip_address = ip_address,
            .packet_id = packet_id,
        };
    }

    /// Reverse lookup on a given ipv4 ip address
    /// Returns an array of N Dns Names resolved from reverse lookup
    fn lookupIpv4(self: Self) ![]const u8 {
        var add = try address.IpAddress.init(self.allocator, address.AddressMeta.Ipv4().fromString(self.ip_address));
        const arpa_address = try add.reverseIpv4();

        var labels: [6][]const u8 = undefined;
        const apra_address_dns_name = try dns.Name.fromString(arpa_address, &labels);

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
            4096, // Max PRT query DNS packets are usually 104 bytes. This could be much smaller
            .{ .name_pool = &name_pool },
        );
        defer reply.deinit(.{ .names = false });

        const reply_packet = reply.packet;

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
    }

    /// Reverse lookup on a given ipv6 ip address
    fn lookupIpv6(self: Self) void {
        _ = self;
    }
};

test "reverse lookup of Ipv4 address" {
    const name = "dns.google.";
    const reverse = try ReverseLookup.init(std.heap.page_allocator, "8.8.4.4", 123);
    const names = try reverse.lookupIpv4();
    std.debug.print("{any}", .{names});

    assert(names.len > 0);
    assert(std.mem.eql(u8, names[0], name));
}
