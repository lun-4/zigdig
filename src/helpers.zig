const std = @import("std");
const dns = @import("lib.zig");

fn printList(
    name_pool: *dns.NamePool,
    writer: anytype,
    resource_list: []dns.Resource,
) !void {
    // TODO the formatting here is not good...
    try writer.print(";;name\t\t\trrtype\tclass\tttl\trdata\n", .{});

    for (resource_list) |resource| {
        const resource_data = try dns.ResourceData.fromOpaque(
            resource.typ,
            resource.opaque_rdata.?,
            .{
                .name_provider = .{ .full = name_pool },
                .allocator = name_pool.allocator,
            },
        );
        defer switch (resource_data) {
            .TXT => resource_data.deinit(name_pool.allocator),
            else => {}, // names are owned by given NamePool
        };

        try writer.print("{?}\t\t{s}\t{s}\t{d}\t{any}\n", .{
            resource.name.?,
            @tagName(resource.typ),
            @tagName(resource.class),
            resource.ttl,
            resource_data,
        });
    }

    try writer.print("\n", .{});
}

/// Print a packet in the format of a "zone file".
///
/// This will deserialize resourcedata in the resource sections, so
/// a NamePool instance is required.
///
/// This helper method will NOT free the memory created by name allocation,
/// you should do this manually in a defer block calling NamePool.deinitWithNames.
pub fn printAsZoneFile(
    packet: *dns.Packet,
    name_pool: *dns.NamePool,
    writer: anytype,
) !void {
    try writer.print(";; opcode: {}, status: {}, id: {}\n", .{
        packet.header.opcode,
        packet.header.response_code,
        packet.header.id,
    });

    try writer.print(";; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n", .{
        packet.header.question_length,
        packet.header.answer_length,
        packet.header.nameserver_length,
        packet.header.additional_length,
    });

    if (packet.header.question_length > 0) {
        try writer.print(";; QUESTION SECTION:\n", .{});
        try writer.print(";;name\ttype\tclass\n", .{});

        for (packet.questions) |question| {
            try writer.print(";{?}\t{s}\t{s}\n", .{
                question.name,
                @tagName(question.typ),
                @tagName(question.class),
            });
        }

        try writer.print("\n", .{});
    }

    if (packet.header.answer_length > 0) {
        try writer.print(";; ANSWER SECTION:\n", .{});
        try printList(name_pool, writer, packet.answers);
    } else {
        try writer.print(";; no answer\n", .{});
    }

    if (packet.header.nameserver_length > 0) {
        try writer.print(";; AUTHORITY SECTION:\n", .{});
        try printList(name_pool, writer, packet.nameservers);
    } else {
        try writer.print(";; no authority\n\n", .{});
    }

    if (packet.header.additional_length > 0) {
        try writer.print(";; ADDITIONAL SECTION:\n", .{});
        try printList(name_pool, writer, packet.additionals);
    } else {
        try writer.print(";; no additional\n\n", .{});
    }
}

/// Generate a random header ID to use in a query.
pub fn randomHeaderId() u16 {
    const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
    var r = std.rand.DefaultPrng.init(seed);
    return r.random().int(u16);
}

/// High level wrapper around a single UDP connection to send and receive
/// DNS packets.
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

        const result = buffer[0..written_bytes];
        const dest_len: u32 = switch (self.address.any.family) {
            std.posix.AF.INET => @sizeOf(std.posix.sockaddr.in),
            std.posix.AF.INET6 => @sizeOf(std.posix.sockaddr.in6),
            else => unreachable,
        };

        _ = try std.posix.sendto(
            self.socket.handle,
            result,
            0,
            &self.address.any,
            dest_len,
        );
    }

    /// Deserializes and allocates an *entire* DNS packet.
    ///
    /// This function is not encouraged if you only wish to get A/AAAA
    /// records for a domain name through the system DNS resolver, as this
    /// allocates all the data of the packet. Use `receiveTrustedAddresses`
    /// for such.
    pub fn receiveFullPacket(
        self: Self,
        packet_allocator: std.mem.Allocator,
        /// Maximum size for the incoming UDP datagram
        comptime max_incoming_message_size: usize,
        options: ParseFullPacketOptions,
    ) !dns.IncomingPacket {
        var packet_buffer: [max_incoming_message_size]u8 = undefined;
        const read_bytes = try self.socket.read(&packet_buffer);
        const packet_bytes = packet_buffer[0..read_bytes];
        logger.debug("read {d} bytes", .{read_bytes});

        var stream = std.io.FixedBufferStream([]const u8){
            .buffer = packet_bytes,
            .pos = 0,
        };
        return parseFullPacket(stream.reader(), packet_allocator, options);
    }
};

pub const ParseFullPacketOptions = struct {
    /// Use this NamePool to let deserialization of names outlive the call
    /// to parseFullPacket.
    ///
    /// Useful if you need to parse RDATA sections after parseFullPacket.
    name_pool: ?*dns.NamePool = null,
};

pub fn parseFullPacket(
    reader: anytype,
    allocator: std.mem.Allocator,
    parse_full_packet_options: ParseFullPacketOptions,
) !dns.IncomingPacket {
    const parser_options = dns.ParserOptions{ .allocator = allocator };

    var packet = try allocator.create(dns.Packet);
    errdefer allocator.destroy(packet);
    const incoming_packet = dns.IncomingPacket{
        .allocator = allocator,
        .packet = packet,
    };

    var ctx = dns.ParserContext{};
    var parser = dns.parser(reader, &ctx, parser_options);

    var builtin_name_pool = dns.NamePool.init(allocator);
    defer builtin_name_pool.deinit();

    var name_pool = if (parse_full_packet_options.name_pool) |name_pool|
        name_pool
    else
        &builtin_name_pool;

    var questions = std.ArrayList(dns.Question).init(allocator);
    defer questions.deinit();

    var answers = std.ArrayList(dns.Resource).init(allocator);
    defer answers.deinit();

    var nameservers = std.ArrayList(dns.Resource).init(allocator);
    defer nameservers.deinit();

    var additionals = std.ArrayList(dns.Resource).init(allocator);
    defer additionals.deinit();

    while (try parser.next()) |part| {
        switch (part) {
            .header => |header| packet.header = header,
            .question => |question_with_raw_names| {
                const question =
                    try name_pool.transmuteResource(question_with_raw_names);
                try questions.append(question);
            },
            .end_question => packet.questions = try questions.toOwnedSlice(),
            .answer, .nameserver, .additional => |raw_resource| {
                // since we give it an allocator, we don't receive rdata frames
                const resource = try name_pool.transmuteResource(raw_resource);
                try (switch (part) {
                    .answer => answers,
                    .nameserver => nameservers,
                    .additional => additionals,
                    else => unreachable,
                }).append(resource);
            },
            .end_answer => packet.answers = try answers.toOwnedSlice(),
            .end_nameserver => packet.nameservers = try nameservers.toOwnedSlice(),
            .end_additional => packet.additionals = try additionals.toOwnedSlice(),
            .answer_rdata, .nameserver_rdata, .additional_rdata => unreachable,
        }
    }

    return incoming_packet;
}

const logger = std.log.scoped(.dns_helpers);

/// Open a socket to the DNS resolver specified in input parameter
pub fn connectToResolver(address: []const u8) !DNSConnection {
    const addr = try std.net.Address.resolveIp(address, 53);

    const flags: u32 = std.os.SOCK.DGRAM;
    const fd = try std.os.socket(addr.any.family, flags, std.os.IPPROTO.UDP);

    return DNSConnection{
        .address = addr,
        .socket = std.net.Stream{ .handle = fd },
    };
}

/// Open a socket to a random DNS resolver declared in the systems'
/// "/etc/resolv.conf" file.
pub fn connectToSystemResolver() !DNSConnection {
    var out_buffer: [256]u8 = undefined;
    const nameserver_address_string = (try randomNameserver(&out_buffer)).?;

    const addr = try std.net.Address.resolveIp(nameserver_address_string, 53);

    const flags: u32 = std.posix.SOCK.DGRAM;
    const fd = try std.posix.socket(addr.any.family, flags, std.posix.IPPROTO.UDP);

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

    const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))));
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

                @memcpy(output_buffer, nameserver_addr);
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

const ReceiveTrustedAddressesOptions = struct {
    max_incoming_message_size: usize = 4096,
    requested_packet_header: ?dns.Header = null,
};

/// This is an optimized deserializer that is only interested in A and AAAA
/// answers, returning a list of std.net.Address.
///
/// This function trusts the DNS connection to be returning answers related
/// to the given domain sent through DNSConnection.sendPacket.
///
/// This, however, does not allocate the packet. It is very memory efficient
/// in that regard.
pub fn receiveTrustedAddresses(
    allocator: std.mem.Allocator,
    connection: *const DNSConnection,
    /// Options to receive message and deserialize it
    comptime options: ReceiveTrustedAddressesOptions,
) ![]std.net.Address {
    var packet_buffer: [options.max_incoming_message_size]u8 = undefined;
    const read_bytes = try connection.socket.read(&packet_buffer);
    const packet_bytes = packet_buffer[0..read_bytes];
    logger.debug("read {d} bytes", .{read_bytes});

    var stream = std.io.FixedBufferStream([]const u8){
        .buffer = packet_bytes,
        .pos = 0,
    };

    var ctx = dns.ParserContext{};

    var parser = dns.parser(stream.reader(), &ctx, .{});

    var addrs = std.ArrayList(std.net.Address).init(allocator);
    errdefer addrs.deinit();

    var current_resource: ?dns.Resource = null;

    while (try parser.next()) |part| {
        switch (part) {
            .header => |header| {
                if (options.requested_packet_header) |given_header| {
                    if (given_header.id != header.id)
                        return error.InvalidReply;
                }

                if (!header.is_response) return error.InvalidResponse;

                switch (header.response_code) {
                    .NoError => {},
                    .FormatError => return error.ServerFormatError, // bug in implementation caught by server?
                    .ServerFailure => return error.ServerFailure,
                    .NameError => return error.ServerNameError,
                    .NotImplemented => return error.ServerNotImplemented,
                    .Refused => return error.ServerRefused,
                }
            },
            .answer => |raw_resource| {
                current_resource = raw_resource;
            },

            .answer_rdata => |rdata| {
                // TODO parser.reader()?
                var reader = parser.wrapper_reader.reader();
                defer current_resource = null;
                const maybe_addr = switch (current_resource.?.typ) {
                    .A => blk: {
                        var ip4addr: [4]u8 = undefined;
                        _ = try reader.read(&ip4addr);
                        break :blk std.net.Address.initIp4(ip4addr, 0);
                    },
                    .AAAA => blk: {
                        var ip6_addr: [16]u8 = undefined;
                        _ = try reader.read(&ip6_addr);
                        break :blk std.net.Address.initIp6(ip6_addr, 0, 0, 0);
                    },
                    else => blk: {
                        try reader.skipBytes(rdata.size, .{});
                        break :blk null;
                    },
                };

                if (maybe_addr) |addr| try addrs.append(addr);
            },
            else => {},
        }
    }

    return try addrs.toOwnedSlice();
}

fn fetchTrustedAddresses(
    allocator: std.mem.Allocator,
    name: dns.Name,
    qtype: dns.ResourceType,
) ![]std.net.Address {
    var questions = [_]dns.Question{
        .{
            .name = name,
            .typ = qtype,
            .class = .IN,
        },
    };

    const packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &questions,
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    const conn = try dns.helpers.connectToSystemResolver();
    defer conn.close();

    logger.debug("selected nameserver: {}", .{conn.address});
    try conn.sendPacket(packet);
    return try receiveTrustedAddresses(allocator, &conn, .{});
}

/// A getAddressList-like function that:
///  - gets a nameserver from resolv.conf
///  - starts a DNSConnection
///  - extracts A/AAAA records and turns them into std.net.Address
///
/// The only memory allocated here is for the list that holds std.net.Address.
///
/// This function does not implement the "happy eyeballs" algorithm.
pub fn getAddressList(incoming_name: []const u8, allocator: std.mem.Allocator) !AddressList {
    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString(incoming_name, &name_buffer);

    var final_list = std.ArrayList(std.net.Address).init(allocator);
    defer final_list.deinit();

    const addrs_v4 = try fetchTrustedAddresses(allocator, name, .A);
    defer allocator.free(addrs_v4);
    for (addrs_v4) |addr| try final_list.append(addr);

    const addrs_v6 = try fetchTrustedAddresses(allocator, name, .AAAA);
    defer allocator.free(addrs_v6);
    for (addrs_v6) |addr| try final_list.append(addr);

    return AddressList{
        .allocator = allocator,
        .addrs = try final_list.toOwnedSlice(),
    };
}
