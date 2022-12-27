# zigdig

naive dns client library in zig

## what does it do
 - serialization and deserialization of dns packets as per rfc1035
 - supports a subset of rdata (A and AAAA are there, so, for most cases, this
 will be enough)
 - has helpers for reading `/etc/resolv.conf` (not that much, really)

## what does it not do
 - no edns0
 - support all resolv.conf options
 - can deserialize pointer labels (seamless for library user), but does not
    serialize into pointers
 - follow CNAME records

## how do

 - zig master branch: https://ziglang.org
 - have a `/etc/resolv.conf`
 - tested on linux, should work on bsd i think

```
git clone ...
cd zigdig

zig build test
zig build install --prefix ~/.local/
```

and then

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
