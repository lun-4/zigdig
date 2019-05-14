// helper functions to read data off /etc/resolv.conf
const std = @import("std");
const os = std.os;
const mem = std.mem;

const NameserverList = [10][]const u8;

fn processResolvLine(
    line: []const u8,
    nameservers: *NameserverList,
    idx: *usize,
) void {
    // ignore everything that isn't a nameserver decl
    if (!mem.startsWith(u8, line, "nameserver ")) return;

    var ns_it = std.mem.separate(line, " ");
    _ = ns_it.next().?;

    nameservers[idx.*] = ns_it.next().?;
    idx.* += 1;
}

pub fn readNameservers() !NameserverList {
    var file = try os.File.openRead("/etc/resolv.conf");
    errdefer file.close();

    // empty slice to start with
    // also initialize it to all zero which is good enough.
    // maybe, in the future, we can speed this up by only setting the
    // first byte as 0
    var nameservers: NameserverList = undefined;

    // read file and put it all in memory, which is kinda
    // sad that we need to do this, but that's life. maybe a better
    // approach would be adding an iterator to file to go through lines
    // that reads bytes until '\n'. a reasonable buffer would be created
    // for each line, of course.

    var buffer: [1024]u8 = undefined;
    var bytes_read = try file.read(&buffer);
    var it = mem.tokenize(buffer, "\n");
    var idx: usize = 0;

    while (it.next()) |line| {
        processResolvLine(line, &nameservers, &idx);
    }

    return nameservers;
}

test "reading /etc/resolv.conf" {
    var nameservers = try readNameservers();
}
