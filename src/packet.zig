const std = @import("std");
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
        return fmt.bufPrint(&buf, "DNSHeader<qd={},an={},ns={},ar={}>", self.qdcount, self.ancount, self.nscount, self.arcount);
    }
};

// TODO
pub const DNSQuestion = struct {};
pub const DNSAnswer = struct {};
pub const DNSAuthority = struct {};
pub const DNSAdditional = struct {};

pub const DNSPacket = struct {
    const Self = @This();

    pub header: DNSHeader,
    pub questions: []DNSQuestion,
    pub answer: []DNSAnswer,
    pub authority: []DNSAuthority,
    pub additional: []DNSAdditional,

    pub fn init() DNSPacket {
        var self = DNSPacket{
            .header = DNSHeader.init(),
            .questions = []DNSQuestion{},
            .answer = []DNSAnswer{},
            .authority = []DNSAuthority{},
            .additional = []DNSAdditional{},
        };
        return self;
    }

    pub fn as_str(self: *DNSPacket) ![]u8 {
        var buf: [1024]u8 = undefined;
        return fmt.bufPrint(&buf, "DNSPacket<{}>", self.header.as_str());
    }
};

test "packet init" {
    var packet = DNSPacket{};
}
