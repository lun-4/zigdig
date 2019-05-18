# zigdig

naive dns client library in zig
 - serialization and deserialization of dns packets as per rfc1035
 - supports a subset of rdata (A and AAAA are there, so, for most cases, this
 will be enough. this library does not follow CNAMEs)
 - has helpers for reading `/etc/resolv.conf` (not that much, really)
 - no edns0

## how do

 - zig zag zog https://ziglang.org
 - have a `/etc/resolv.conf`
 - (theoretical) posix os w/ sockets, tested on linux
 - have The Internet (TM) at your disposal

```
zig build test

# on debug mode it gets debug stuff to stdout. compile in
# release-safe or above if you're not developing with this lib
zig build install --prefix ~/.local/
```

```bash
# rn only numerical QTYPE is allowed. (TODO nicer QTYPE parse/unparse)
# QCLASS is default IN

zigdig google.com 1
```

## using the library

it is recommended to look at zigdig's source on `src/main.zig` to understand
how things tick using the library, but it boils down to three things:
 - packet generation and serialization
 - sending/receiving (via a small shim on top of std.os.posixSocket)
 - packet deserialization
