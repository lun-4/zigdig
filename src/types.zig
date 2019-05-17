// DNS QTYPE

pub const DNSType = enum(u16) {
    A = 1,
    NS,
    MD,
    MF,
    CNAME = 5,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,

    AAAA = 28,
    //LOC,
    //SRV,

    // QTYPE only, but merging under DNSType
    // for nicer API

    // TODO: add them back, maybe?
    //AXFR = 252,
    //MAILB,
    //MAILA,
    //WILDCARD,
};

pub const DNSClass = enum(u16) {
    IN = 1,
    CS,
    CH,
    HS,
    WILDCARD = 255,
};

/// Convert a DNSType u16 into a string representing it.
pub fn typeToStr(qtype: u16) []const u8 {
    const type_info = @typeInfo(DNSType).Enum;
    var as_dns_type = @intToEnum(DNSType, qtype);

    inline for (type_info.fields) |field| {
        if (field.value == qtype) {
            return field.name;
        }
    }

    return "<unknown>";
}
