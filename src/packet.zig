const std = @import("std");
const rand = std.rand;
const os = std.os;
const testing = std.testing;
const fmt = std.fmt;

pub const DNSHeader = packed struct {
    id: u16,
    qr_flag: bool,
    opcode: i4,

    aa_flag: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u3,
    rcode: u4,

    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub fn init() DNSHeader {
        var self = DNSHeader{
            .id = 0,
            .qr_flag = false,
            .opcode = 0,
            .aa_flag = false,
            .tc = false,
            .rd = false,
            .ra = false,
            .z = 0,
            .rcode = 0,
            .qdcount = 0,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };

        return self;
    }

    pub fn as_str(self: *DNSHeader) ![]u8 {
        var buf: [1024]u8 = undefined;
        return fmt.bufPrint(&buf, "DNSHeader<id={},qd={},an={},ns={},ar={}>", self.id, self.qdcount, self.ancount, self.nscount, self.arcount);
    }

    pub fn export_out(self: *DNSHeader) []u8 {
        var aligned = @alignCast(@alignOf([]u8), self);
        return @ptrCast(*[]u8, aligned).*;
    }
};

// TODO
pub const DNSQuestion = packed struct {
    pub fn export_out(self: *DNSQuestion) []u8 {
        return "";
    }
};

pub const DNSResource = packed struct {
    pub fn export_out(self: *DNSResource) []u8 {
        return "";
    }
};

pub const DNSPacket = struct {
    const Self = @This();
    pub const Error = error{};

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answers: []DNSResource,
    pub authority: []DNSResource,
    pub additional: []DNSResource,

    pub fn init() DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),
            .questions = []DNSQuestion{},
            .answers = []DNSResource{},
            .authority = []DNSResource{},
            .additional = []DNSResource{},
        };
        return self;
    }

    pub fn fill(self: *DNSPacket, buffer: std.io.InStream(Error)) void {
        // TODO: read
        return;
    }

    pub fn as_str(self: *DNSPacket) ![]u8 {
        var buf: [1024]u8 = undefined;
        return fmt.bufPrint(&buf, "DNSPacket<{}>", self.header.as_str());
    }

    pub fn is_valid(self: *DNSPacket) bool {
        var valid = (self.questions.len == self.header.qdcount and
            self.answer.len == self.ancount and
            self.authority.len == self.nscount and
            self.additional == self.arcount);
        return valid;
    }

    pub fn export_out(self: *DNSPacket, buffer: []u8) ![]u8 {
        return try std.fmt.bufPrint(buffer, "{}{}{}{}{}", self.header.export_out(), try self.export_qdlist(buffer), try self.export_list(self.answers, buffer), try self.export_list(self.authority, buffer), try self.export_list(self.additional, buffer));
    }

    fn export_qdlist(self: *DNSPacket, buffer: []u8) ![]u8 {
        // TODO: this should maybe be better. probably giving both
        // buffer and out as args
        var out: []u8 = undefined;

        for (self.questions) |question| {
            var qd_out = question.export_out();

            // simple concat using bufPrint
            out = try fmt.bufPrint(buffer, "{}{}", out, qd_out);
        }

        return out;
    }

    fn export_list(self: *DNSPacket, list: []DNSResource, buffer: []u8) ![]u8 {
        var out: []u8 = undefined;

        for (list) |resource| {
            var rs_out = resource.export_out();
            out = try fmt.bufPrint(buffer, "{}{}", out, rs_out);
        }

        return out;
    }
};

test "packet init" {
    var packet = DNSPacket.init();
    var r = rand.DefaultPrng.init(os.time.timestamp());

    packet.header.id = r.random.int(u16);

    var buf: [5012]u8 = undefined;
    const exported = packet.export_out(&buf);
    std.debug.warn("\nexported: '{}'\n", exported);
    std.debug.warn("\n{}\n", @typeName(@typeOf(exported)));
    // packet.fill etc
}
