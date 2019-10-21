# zigdig

naive dns client library in zig

## what does it do
 - serialization and deserialization of dns packets as per rfc1035
 - supports a subset of rdata (A and AAAA are there, so, for most cases, this
 will be enough)
 - has helpers for reading `/etc/resolv.conf` (not that much, really)

## what does it not do
 - no edns0
 - can deserialize pointer labels (seamless for library user), but does not
    serialize into pointers
 - follow CNAME records

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
zigdig google.com a
```

## using the library

**TODO docs**

it is recommended to look at zigdig's source on `src/main.zig` to understand
how things tick using the library, but it boils down to three things:
 - packet generation and serialization
 - sending/receiving (via a small shim on top of std.os.socket)
 - packet deserialization
