// helper functions to read data off /etc/resolv.conf
const std = @import("std");
const os = std.os;
const mem = std.mem;

const NameserverList = [10][256]u8;

fn processResolvLine(
    line: []const u8,
    nameservers: *NameserverList,
    idx: *usize,
) void {
    // ignore everything that isn't a nameserver decl
    if (!mem.startsWith(u8, line, "nameserver ")) return;

    var ns_it = std.mem.separate(line, " ");
    _ = ns_it.next().?;

    // convert incoming []const u8 into [256]u8.
    var ns_ip = ns_it.next().?;

    var ns_ip_nice: [256]u8 = undefined;
    std.mem.copy(u8, &ns_ip_nice, ns_ip);

    nameservers[idx.*] = ns_ip_nice;
    idx.* += 1;
}

pub fn readNameservers() !NameserverList {
    var file = try os.File.openRead("/etc/resolv.conf");
    errdefer file.close();

    // empty slice to start with
    var nameservers: NameserverList = undefined;

    // read file and put it all in memory, which is kinda
    // sad that we need to do this, but that's life. maybe a better
    // approach would be adding an iterator to file to go through lines
    // that reads bytes until '\n'. a reasonable buffer would be created
    // for each line, of course.

    var buffer: [1024]u8 = undefined;
    var bytes_read = try file.read(&buffer);
    var it = mem.separate(buffer, "\n");
    var idx: usize = 0;

    while (it.next()) |line| {
        processResolvLine(line, &nameservers, &idx);
    }

    return nameservers;
}

test "reading /etc/resolv.conf" {
    var nameservers = try readNameservers();
}
