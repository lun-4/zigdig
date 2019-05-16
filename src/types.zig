// DNS QTYPE

const DNSType = enum {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
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
};

const DNSQType = enum {
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    WILDCARD = 255,
};

const DNSClass = enum {
    IN = 1,
    CS,
    CH,
    HS,
};

const DNSQClass = enum {
    WILDCARD = 255,
};
