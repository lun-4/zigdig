const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.dns_parser);

/// Create a Parser object out of a reader, context, and options.
///
/// If you do not wish to have full control over deserialization, look at
/// dns.helpers.parseFullPacket, which is a wrapper around the Parser that
/// allocates everything.
pub fn parser(
    reader: anytype,
    ctx: *ParserContext,
    options: dns.ParserOptions,
) Parser(@TypeOf(reader)) {
    return Parser(@TypeOf(reader)).init(reader, ctx, options);
}

pub const ResourceResolutionOptions = struct {
    max_follow: usize = 32,
};

const ParserState = enum {
    header,
    question,
    answer,
    nameserver,
    additional,
    answer_rdata,
    nameserver_rdata,
    additional_rdata,
    done,
};

/// A given frame from the parser, depending on the given options, some frames
/// will not be emitted by Parser.next, look at options for more information.
pub const ParserFrame = union(enum) {
    header: dns.Header,

    question: dns.Question,
    end_question: void,

    answer: dns.Resource,
    answer_rdata: dns.parserlib.ResourceDataHolder,
    end_answer: void,

    nameserver: dns.Resource,
    nameserver_rdata: dns.parserlib.ResourceDataHolder,
    end_nameserver: void,

    additional: dns.Resource,
    additional_rdata: dns.parserlib.ResourceDataHolder,
    end_additional: void,
};

pub const ResourceDataHolder = struct {
    size: usize,
    current_byte_index: usize,

    pub fn skip(self: @This(), reader: anytype) !void {
        try reader.skipBytes(self.size, .{});
    }

    pub fn readAllAlloc(
        self: @This(),
        allocator: std.mem.Allocator,
        reader: anytype,
    ) !dns.ResourceData.Opaque {
        const opaque_rdata = try allocator.alloc(u8, self.size);
        const read_bytes = try reader.read(opaque_rdata);
        std.debug.assert(read_bytes == opaque_rdata.len);
        return .{
            .data = opaque_rdata,
            .current_byte_count = self.current_byte_index,
        };
    }
};

pub const ParserOptions = struct {
    /// When given an allocator, the following happens:
    ///  - the parser creates RawName or FullName entities for the
    ///    respective entities with names on them.
    ///    (RawName when names end in Pointers, FullName when not)
    ///  - the parser will automatically allocate RDATA sections inside
    ///    Resource entities. It is on the parser's client to free the memory
    ///    (e.g by putting it inside an IncomingPacket's Packet)
    ///
    /// If allocator is null, the following happens:
    ///  - The name fields will be set to null.
    ///  - answer_rdata, nameserver_rdata, additional_rdata events are
    ///    emitted so the client of the Parser interface can decide if they
    ///    will be allocated, or parsed onto the stack, or something else.
    ///
    /// It is required to pass an allocator to have any access to name
    /// information. We can't parse the names in a standalone manner as
    /// they are usually the *first* field in a Question or Resource, so we
    /// need to decide if we read and allocate, or skip and don't.
    allocator: ?std.mem.Allocator = null,

    /// The maximum amount of labels in a name while parsing.
    ///
    /// Makes parser return `error.Overflow` when
    /// the given name to deserialize surpasses the value in this field.
    max_label_size: usize = 32,
};

pub const ParserContext = struct {
    header: ?dns.Header = null,
    current_byte_count: usize = 0,
    current_counts: struct {
        question: usize = 0,
        answer: usize = 0,
        nameserver: usize = 0,
        additional: usize = 0,
    } = .{},
};

pub const DeserializationContext = struct {
    current_byte_count: usize = 0,
};

/// Wrap a Reader with a type that contains a DeserializationContext.
///
/// Automatically increments the DeserializationContext's current_byte_count
/// on every read().
///
/// Useful to hold deserialization state without having to pass an entire
/// parameter around on every single helper function.
pub fn WrapperReader(comptime ReaderType: anytype) type {
    return struct {
        underlying_reader: ReaderType,
        ctx: *ParserContext,

        const Self = @This();

        pub fn read(self: *Self, buffer: []u8) !usize {
            const bytes_read = try self.underlying_reader.read(buffer);
            self.ctx.current_byte_count += bytes_read;
            logger.debug(
                "wrapper reader: read {d} bytes, now at {d}",
                .{ bytes_read, self.ctx.current_byte_count },
            );
            return bytes_read;
        }

        pub const Error = ReaderType.Error;
        pub const Reader = std.io.Reader(*Self, Error, read);
        pub fn reader(self: *Self) Reader {
            return Reader{ .context = self };
        }
    };
}

/// Low level parser for DNS packets.
///
/// There are two wrappers for this parser, dns.helpers.parseFullPacket,
/// and dns.helpers.receiveTrustedAddresses.
pub fn Parser(comptime ReaderType: type) type {
    const WrapperR = WrapperReader(ReaderType);

    return struct {
        state: ParserState = .header,
        wrapper_reader: WrapperR,
        options: ParserOptions,
        ctx: *ParserContext,

        const Self = @This();

        pub fn init(
            incoming_reader: ReaderType,
            ctx: *ParserContext,
            options: ParserOptions,
        ) Self {
            const self = Self{
                .wrapper_reader = WrapperR{
                    .underlying_reader = incoming_reader,
                    .ctx = ctx,
                },
                .options = options,
                .ctx = ctx,
            };

            return self;
        }

        /// Receive the next frame from the parser.
        pub fn next(self: *Self) !?ParserFrame {
            // self.state dictates what we *want* from the reader
            // at the moment, first state always being header.
            logger.debug("next(): enter {}", .{self.state});

            logger.debug(
                "parser reader is at {d} bytes of message",
                .{self.wrapper_reader.ctx.current_byte_count},
            );

            var reader = self.wrapper_reader.reader();

            switch (self.state) {
                .header => {
                    // since header is constant size, store it
                    // in our parser state so we know how to continue
                    const header = try dns.Header.readFrom(reader);
                    self.ctx.header = header;
                    self.state = .question;
                    logger.debug(
                        "next(): header read ({?}). state is now {}",
                        .{ self.ctx.header, self.state },
                    );
                    return ParserFrame{ .header = header };
                },
                .question => {
                    logger.debug("next(): read {d} out of {d} questions", .{
                        self.ctx.current_counts.question,
                        self.ctx.header.?.question_length,
                    });

                    self.ctx.current_counts.question += 1;

                    if (self.ctx.current_counts.question > self.ctx.header.?.question_length) {
                        self.state = .answer;
                        logger.debug("parser: end question, go to resources", .{});
                        return ParserFrame{ .end_question = {} };
                    } else {
                        const raw_question = try dns.Question.readFrom(reader, self.options);
                        return ParserFrame{ .question = raw_question };
                    }
                },
                .answer, .nameserver, .additional => {
                    const count_holder = (switch (self.state) {
                        .answer => &self.ctx.current_counts.answer,
                        .nameserver => &self.ctx.current_counts.nameserver,
                        .additional => &self.ctx.current_counts.additional,
                        else => unreachable,
                    });

                    const header_count = switch (self.state) {
                        .answer => self.ctx.header.?.answer_length,
                        .nameserver => self.ctx.header.?.nameserver_length,
                        .additional => self.ctx.header.?.additional_length,
                        else => unreachable,
                    };

                    logger.debug("next(): read {d} out of {d} resources", .{
                        count_holder.*, header_count,
                    });

                    count_holder.* += 1;

                    if (count_holder.* > header_count) {
                        const old_state = self.state;
                        self.state = switch (self.state) {
                            .answer => .nameserver,
                            .nameserver => .additional,
                            .additional => .done,
                            else => unreachable,
                        };

                        logger.debug(
                            "end resource list. state transition {} -> {}",
                            .{ old_state, self.state },
                        );

                        return switch (old_state) {
                            .answer => ParserFrame{ .end_answer = {} },
                            .nameserver => ParserFrame{ .end_nameserver = {} },
                            .additional => ParserFrame{ .end_additional = {} },
                            else => unreachable,
                        };
                    } else {
                        const raw_resource = try dns.Resource.readFrom(reader, self.options);

                        // not at end yet, which means resource_rdata event
                        // must happen if we don't have allocator

                        const old_state = self.state;

                        // if we don't have allocator, we emit rdata records
                        if (self.options.allocator == null) {
                            self.state = switch (self.state) {
                                .answer => .answer_rdata,
                                .nameserver => .nameserver_rdata,
                                .additional => .additional_rdata,
                                else => unreachable,
                            };
                        }

                        logger.debug("resource from {}: {}", .{ old_state, raw_resource });

                        return switch (old_state) {
                            .answer => ParserFrame{ .answer = raw_resource },
                            .nameserver => ParserFrame{ .nameserver = raw_resource },
                            .additional => ParserFrame{ .additional = raw_resource },
                            else => unreachable,
                        };
                    }
                },

                .answer_rdata, .nameserver_rdata, .additional_rdata => {
                    const old_state = self.state;

                    self.state = switch (self.state) {
                        .answer_rdata => .answer,
                        .nameserver_rdata => .nameserver,
                        .additional_rdata => .additional,
                        else => unreachable,
                    };

                    const rdata_length = try reader.readInt(u16, .big);
                    const rdata_index = reader.context.ctx.current_byte_count;
                    const rdata = ResourceDataHolder{
                        .size = rdata_length,
                        .current_byte_index = rdata_index,
                    };

                    return switch (old_state) {
                        .answer_rdata => ParserFrame{ .answer_rdata = rdata },
                        .nameserver_rdata => ParserFrame{ .nameserver_rdata = rdata },
                        .additional_rdata => ParserFrame{ .additional_rdata = rdata },
                        else => unreachable,
                    };
                },

                .done => return null,
            }
        }
    };
}
