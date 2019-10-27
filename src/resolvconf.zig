// helper functions to read data off /etc/resolv.conf
const std = @import("std");
const os = std.os;
const mem = std.mem;

pub const NameserverList = std.ArrayList([]const u8);

/// Read the `/etc/resolv.conf` file in the system and return a list
/// of nameserver addresses
pub fn readNameservers(allocator: *std.mem.Allocator) !NameserverList {
    var file = try std.fs.File.openRead("/etc/resolv.conf");
    defer file.close();

    var nameservers = NameserverList.init(allocator);
    errdefer nameservers.deinit();

    // TODO maybe a better approach would be adding an iterator
    // to file to go through lines that reads bytes until '\n'.

    const total_bytes = try file.getEndPos();
    var buf = try allocator.alloc(u8, total_bytes);
    errdefer allocator.free(buf);

    _ = try file.read(buf);

    var it = mem.tokenize(buf, "\n");
    while (it.next()) |line| {
        if (!mem.startsWith(u8, line, "nameserver ")) continue;

        var ns_it = std.mem.separate(line, " ");
        _ = ns_it.next().?;
        try nameservers.append(ns_it.next().?);
    }

    return nameservers;
}

test "reading /etc/resolv.conf" {
    var nameservers = try readNameservers(std.heap.direct_allocator);
}
