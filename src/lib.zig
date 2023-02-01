pub const ResourceType = @import("enums.zig").ResourceType;
pub const ResourceClass = @import("enums.zig").ResourceClass;

pub const names = @import("name.zig");
pub const FullName = names.FullName;
pub const RawName = names.RawName;
pub const Name = names.Name;
pub const LabelComponent = names.LabelComponent;

const pkt = @import("packet.zig");
pub const Packet = pkt.Packet;
pub const ResponseCode = pkt.ResponseCode;
pub const OpCode = pkt.OpCode;
pub const IncomingPacket = pkt.IncomingPacket;
pub const Question = pkt.Question;
pub const Resource = pkt.Resource;
pub const Header = pkt.Header;

const parser_lib = @import("parser.zig");
pub const parser = parser_lib.parser;
pub const Parser = parser_lib.Parser;
pub const ParserOptions = parser_lib.ParserOptions;

pub const helpers = @import("helpers.zig");

const resource_data = @import("resource_data.zig");
pub const ResourceData = resource_data.ResourceData;
