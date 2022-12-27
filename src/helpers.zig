const std = @import("std");
const dns = @import("lib.zig");

/// Print a slice of DNSResource to stderr.
fn printList(packet: *dns.Packet, allocator: std.mem.Allocator, writer: anytype, resource_list: []dns.Resource) !void {
    // TODO the formatting here is not good...
    try writer.print(";;name\t\t\trrtype\tclass\tttl\trdata\n", .{});

    for (resource_list) |resource| {
        var resource_data = try dns.ResourceData.fromOpaque(packet, resource.typ, resource.opaque_rdata, allocator);
        defer resource_data.deinit(allocator);

        try writer.print("{s}\t\t{s}\t{s}\t{d}\t{any}\n", .{
            resource.name,
            @tagName(resource.typ),
            @tagName(resource.class),
            resource.ttl,
            resource_data,
        });
    }

    try writer.print("\n", .{});
}

/// Print a packet to stderr.
pub fn printAsZoneFile(packet: *dns.Packet, allocator: std.mem.Allocator, writer: anytype) !void {
    try writer.print("id: {}, opcode: {}, rcode: {}\n", .{
        packet.header.id,
        packet.header.opcode,
        packet.header.response_code,
    });

    try writer.print("qd: {}, an: {}, ns: {}, ar: {}\n\n", .{
        packet.header.question_length,
        packet.header.answer_length,
        packet.header.nameserver_length,
        packet.header.additional_length,
    });

    if (packet.header.question_length > 0) {
        try writer.print(";;-- question --\n", .{});
        try writer.print(";;name\ttype\tclass\n", .{});

        for (packet.questions) |question| {
            try writer.print(";{s}\t{s}\t{s}\n", .{
                question.name,
                @tagName(question.typ),
                @tagName(question.class),
            });
        }

        try writer.print("\n", .{});
    }

    if (packet.header.answer_length > 0) {
        try writer.print(";; -- answer --\n", .{});
        try printList(packet, allocator, writer, packet.answers);
    } else {
        try writer.print(";; no answer\n", .{});
    }

    if (packet.header.nameserver_length > 0) {
        try writer.print(";; -- authority --\n", .{});
        try printList(packet, allocator, writer, packet.nameservers);
    } else {
        try writer.print(";; no authority\n\n", .{});
    }

    if (packet.header.additional_length > 0) {
        try writer.print(";; -- additional --\n", .{});
        try printList(packet, allocator, writer, packet.additionals);
    } else {
        try writer.print(";; no additional\n\n", .{});
    }
}

pub fn randomHeaderId() u16 {
    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);
    return r.random().int(u16);
}

pub const DNSConnection = struct {
    address: std.net.Address,
    socket: std.net.Stream,

    const Self = @This();

    pub fn close(self: Self) void {
        self.socket.close();
    }

    pub fn sendPacket(self: Self, packet: dns.Packet) !void {
        // Stream won't use sendto() when its UDP, so serialize it into
        // a buffer, and then send that
        var buffer: [1024]u8 = undefined;

        const typ = std.io.FixedBufferStream([]u8);
        var stream = typ{ .buffer = &buffer, .pos = 0 };

        const written_bytes = try packet.writeTo(stream.writer());

        var result = buffer[0..written_bytes];
        const dest_len: u32 = switch (self.address.any.family) {
            std.os.AF.INET => @sizeOf(std.os.sockaddr.in),
            std.os.AF.INET6 => @sizeOf(std.os.sockaddr.in6),
            else => unreachable,
        };

        _ = try std.os.sendto(
            self.socket.handle,
            result,
            0,
            &self.address.any,
            dest_len,
        );
    }

    pub fn receivePacket(
        self: Self,
        packet_allocator: std.mem.Allocator,
        comptime max_incoming_message_size: usize,
    ) !dns.IncomingPacket {
        var packet_buffer: [max_incoming_message_size]u8 = undefined;
        const read_bytes = try self.socket.read(&packet_buffer);
        const packet_bytes = packet_buffer[0..read_bytes];
        logger.debug("read {d} bytes", .{read_bytes});

        var stream = std.io.FixedBufferStream([]const u8){ .buffer = packet_bytes, .pos = 0 };
        return try dns.Packet.readFrom(stream.reader(), packet_allocator);
    }
};

const logger = std.log.scoped(.dns_helpers);

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn connectToSystemResolver() !DNSConnection {
    var out_buffer: [256]u8 = undefined;
    const nameserver_address_string = (try randomNameserver(&out_buffer)).?;

    var addr = try std.net.Address.resolveIp(nameserver_address_string, 53);

    var flags: u32 = std.os.SOCK.DGRAM;
    const fd = try std.os.socket(addr.any.family, flags, std.os.IPPROTO.UDP);

    return DNSConnection{
        .address = addr,
        .socket = std.net.Stream{ .handle = fd },
    };
}

pub fn randomNameserver(output_buffer: []u8) !?[]const u8 {
    var file = try std.fs.cwd().openFile(
        "/etc/resolv.conf",
        .{ .mode = .read_only },
    );
    defer file.close();

    // iterate through all lines to find the amount of nameservers, then select
    // a random one, then read AGAIN so that we can return it.
    //
    // this doesn't need any allocator or lists or whatever. just the
    // output buffer

    try file.seekTo(0);
    var line_buffer: [1024]u8 = undefined;
    var nameserver_amount: usize = 0;
    while (try file.reader().readUntilDelimiterOrEof(&line_buffer, '\n')) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.split(u8, line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            nameserver_amount += 1;
        }
    }

    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);
    const selected = r.random().uintLessThan(usize, nameserver_amount);

    try file.seekTo(0);

    var current_nameserver: usize = 0;
    while (try file.reader().readUntilDelimiterOrEof(&line_buffer, '\n')) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.split(u8, line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            if (current_nameserver == selected) {
                const nameserver_addr = ns_it.next().?;

                std.mem.copy(u8, output_buffer, nameserver_addr);
                return output_buffer[0..nameserver_addr.len];
            }

            current_nameserver += 1;
        }
    }

    return null;
}

const AddressList = struct {
    allocator: std.mem.Allocator,
    addrs: []std.net.Address,
    pub fn deinit(self: @This()) void {
        self.allocator.free(self.addrs);
    }
};

/// A very simple getAddressList that sets up the DNS connection and extracts
/// the A records.
///
/// This function does not implement the "happy eyeballs" algorithm.
pub fn getAddressList(incoming_name: []const u8, allocator: std.mem.Allocator) !AddressList {
    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(incoming_name, &name_buffer);

    var packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &[_]dns.Question{
            .{
                .name = name,
                .typ = .A,
                .class = .IN,
            },
        },
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    const conn = try dns.helpers.connectToSystemResolver();
    defer conn.close();

    logger.info("selected nameserver: {}\n", .{conn.address});

    try conn.sendPacket(packet);

    const reply = try conn.receivePacket(allocator, 4096);
    defer reply.deinit();

    const reply_packet = reply.packet;

    if (packet.header.id != reply_packet.header.id) return error.InvalidReply;
    if (!reply_packet.header.is_response) return error.InvalidResponse;

    switch (reply_packet.header.response_code) {
        .NoError => {},
        .FormatError => return error.ServerFormatError, // bug in implementation caught by server?
        .ServerFailure => return error.ServerFailure,
        .NameError => return error.ServerNameError,
        .NotImplemented => return error.ServerNotImplemented,
        .Refused => return error.ServerRefused,
    }

    var list = std.ArrayList(std.net.Address).init(allocator);
    defer list.deinit();

    for (reply_packet.answers) |resource| {
        var resource_data = try dns.ResourceData.fromOpaque(
            reply_packet,
            resource.typ,
            resource.opaque_rdata,
            allocator,
        );
        defer resource_data.deinit(allocator);

        try list.append(resource_data.A);
    }

    return AddressList{
        .allocator = allocator,
        .addrs = list.toOwnedSlice(),
    };
}
