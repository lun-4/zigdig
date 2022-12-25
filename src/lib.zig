pub const ResourceType = @import("enums.zig").ResourceType;
pub const ResourceClass = @import("enums.zig").ResourceClass;
pub const Name = @import("name.zig").Name;
const pkt = @import("packet.zig");
pub const Packet = pkt.Packet;
pub const IncomingPacket = pkt.IncomingPacket;
pub const Question = pkt.Question;
pub const Resource = pkt.Resource;
pub const helpers = @import("helpers.zig");

const resource_data = @import("resource_data.zig");
pub const ResourceData = resource_data.ResourceData;
