pub const DNSError = error{
    UnknownDNSType,
    RDATANotSupported,
    DeserialFail,
    ParseFail,
};
