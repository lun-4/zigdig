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

```zig
const dns = @import("dns");

pub fn main() !void {
    var name_buffer: [128][]const u8 = undefined;
    const name = try dns.Name.fromString("ziglang.org", &name_buffer);

    var packet = dns.Packet{
        .header = .{
            .id = dns.helpers.randomHeaderId(),
            .is_response = false,
            .wanted_recursion = true,
            .question_length = 1,
        },
        .questions = &[_]dns.Question{
            .{
                .name = name,
                .typ = .A,
                .class = .IN,
            },
        },
        .answers = &[_]dns.Resource{},
        .nameservers = &[_]dns.Resource{},
        .additionals = &[_]dns.Resource{},
    };

    // use helper function to connect to a resolver in the systems'
    // resolv.conf

    const conn = try dns.helpers.connectToSystemResolver();
    defer conn.close();

    try conn.sendPacket(packet);

    // you can also do this to support any Writer
    // const written_bytes = try packet.writeTo(some_fun_writer_goes_here);

    const reply = try conn.receivePacket(allocator, 4096);
    defer reply.deinit();

    // you can also do this to support any Reader
    // const packet = try dns.Packet.readFrom(some_fun_reader, allocator);
    // defer packet.deinit();

    const reply_packet = reply.packet;
    logger.info("reply: {}", .{reply_packet});

    try std.testing.expectEqual(packet.header.id, reply_packet.header.id);
    try std.testing.expect(reply_packet.header.is_response);

    // ASSERTS that there's one A resource in the answer!!! you should verify
    // reply_packet.header.opcode to see if there's any errors

    const resource = reply_packet.answers[0];
    var resource_data = try dns.ResourceData.fromOpaque(
        reply_packet,
        resource.typ,
        resource.opaque_rdata,
        allocator
    );
    defer resource_data.deinit(allocator);

    // you now have an std.net.Address
    const ziglang_address = resource_data.A;
}

```

**TODO docs**

it is recommended to look at zigdig's source on `src/main.zig` to understand
how things tick using the library, but it boils down to three things:
 - packet generation and serialization
 - sending/receiving (via a small shim on top of std.os.socket)
 - packet deserialization
