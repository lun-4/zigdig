const std = @import("std");
pub const helpers = @import("./helpers.zig");

pub const ResourceType = @import("./types.zig").ResourceType;
pub const ResourceClass = @import("./types.zig").ResourceClass;
pub const Name = @import("./names.zig").Name;
pub const ResourceData = @import("./rdata.zig").ResourceData;

const packet = @import("./packet.zig");
pub const Question = packet.Question;
pub const Packet = packet.Packet;
pub const Resource = packet.Resource;
pub const DeserializationContext = packet.DeserializationContext;

test "" {
    std.testing.refAllDecls(@import("./test.zig"));
    std.testing.refAllDecls(@This());
}
