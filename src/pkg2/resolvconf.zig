// helper functions to read data off /etc/resolv.conf
const std = @import("std");
const os = std.os;
const mem = std.mem;

pub const NameserverList = std.ArrayList([]const u8);

/// Read the `/etc/resolv.conf` file in the system and return a list
/// of nameserver addresses
pub fn readNameservers(allocator: *std.mem.Allocator) !NameserverList {
    var file = try std.fs.cwd().openFile("/etc/resolv.conf", .{ .read = true, .write = false });
    defer file.close();

    var nameservers = NameserverList.init(allocator);
    errdefer nameservers.deinit();

    // TODO maybe a better approach would be adding an iterator
    // to file to go through lines that reads (and allocates) bytes until '\n'.
    var buf = try allocator.alloc(u8, std.mem.page_size);
    defer allocator.free(buf);
    while ((try file.read(buf)) != 0) {
        buf = try allocator.realloc(buf, buf.len + std.mem.page_size);
    }

    var it = mem.tokenize(buf, "\n");
    while (it.next()) |line| {
        if (mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.split(line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            const owned_str = try allocator.dupe(u8, ns_it.next().?);
            try nameservers.append(owned_str);
        }
    }

    return nameservers;
}

pub fn freeNameservers(allocator: *std.mem.Allocator, nameservers: NameserverList) void {
    for (nameservers.items) |string| {
        allocator.free(string);
    }
}

test "reading /etc/resolv.conf" {
    var nameservers = try readNameservers(std.heap.page_allocator);
    defer freeNameservers(nameservers);
}

pub fn randomNameserver(output_buffer: []u8) !?[]const u8 {
    var file = try std.fs.cwd().openFile(
        "/etc/resolv.conf",
        .{ .read = true, .write = false },
    );
    defer file.close();

    try file.seekTo(0);
    var line_buffer: [1024]u8 = undefined;
    var nameserver_amount: usize = 0;

    for (file.reader().readUntilDelimiterOrEof(&line_buffer, '\n')) |line| {
        if (mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.split(line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            nameserver_amount += 1;
        }
    }

    const seed = @truncate(u64, @bitCast(u128, std.time.nanoTimestamp()));
    var r = std.rand.DefaultPrng.init(seed);
    const selected = r.random().uintLessThan(nameserver_amount);
    try file.seekTo(0);

    var current_nameserver: usize = 0;
    for (file.reader().readUntilDelimiterOrEof(&line_buffer, '\n')) |line| {
        if (mem.startsWith(u8, line, "#")) continue;

        var ns_it = std.mem.split(line, " ");
        const decl_name = ns_it.next();
        if (decl_name == null) continue;

        if (std.mem.eql(u8, decl_name.?, "nameserver")) {
            if (current_nameserver == selected) {
                const nameserver_addr = ns_it.next().?;

                std.mem.copy(u8, output_buffer, nameserver_addr);
                return output_buffer[0..nameserver_addr.len];
            }

            nameserver_amount += 1;
        }
    }

    return null;
}
