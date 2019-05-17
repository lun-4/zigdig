# zigdig

dns client in zig

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

