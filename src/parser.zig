const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.dns_packet);

pub fn parser(
    reader: anytype,
    options: dns.ParserOptions,
) Parser(@TypeOf(reader)) {
    return Parser(@TypeOf(reader)).init(reader, options);
}

fn Output(typ: type) type {
    return switch (typ) {
        dns.Question => dns.Question,
        dns.Resource => dns.Resource,
        else => @compileError("invalid input to resolve"),
    };
}

pub const ResourceResolutionOptions = struct {
    max_follow: usize = 32,
};

pub const NamePool = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    fn resolve(raw_data: anytype, options: ResourceResolutionOptions) Output(@TypeOf(raw_data)) {
        _ = options;
        @compileError("TODO");
    }
};

const ParserState = enum {
    header,
    question,
    end_question,
    answer,
    end_answer,
    nameserver,
    end_nameserver,
    additional,
    end_additional,
};

pub const ParserFrame = union(ParserState) {
    header: dns.Header,

    question: dns.Question,
    end_question: void,

    answer: dns.Resource,
    end_answer: void,

    nameserver: dns.Resource,
    end_nameserver: void,

    additional: dns.Resource,
    end_additional: void,
};

pub const ParserOptions = struct {
    header_aware: bool = true,
    /// Give an allocator if you want names to appear properly.
    allocator: ?std.mem.Allocator = null,
};

const ParserContext = struct {
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
pub fn Parser(comptime ReaderType: type) type {
    const WrapperR = WrapperReader(ReaderType);

    return struct {
        // null means end of packet
        state: ?ParserState = .header,
        reader: WrapperR.Reader,
        options: ParserOptions,
        ctx: ParserContext,

        const Self = @This();

        pub fn init(incoming_reader: ReaderType, options: ParserOptions) Self {
            var self = Self{
                .reader = undefined,
                .options = options,
                .ctx = .{},
            };

            var wrapper_reader = WrapperR{
                .underlying_reader = incoming_reader,
                .ctx = &self.ctx,
            };
            self.reader = wrapper_reader.reader();
            return self;
        }

        pub fn next(self: *Self) !?ParserFrame {
            // self.state dictates what we *want* from the reader
            // at the moment, first state always being header.
            if (self.state) |state| switch (state) {
                .header => {
                    // since header is constant size, store it
                    // in our parser state so we know how to continue
                    const header = try dns.Header.readFrom(self.reader);
                    self.ctx.header = header;
                    self.state = .question;
                    return ParserFrame{ .header = header };
                },
                .question => {
                    const raw_question = try dns.Question.readFrom(self.reader, self.options);
                    self.ctx.current_counts.question += 1;
                    if (self.ctx.current_counts.question > self.ctx.header.?.question_length) {
                        self.state = .answer;
                        return ParserState{ .end_question = .{} };
                    } else {
                        return ParserFrame{ .question = raw_question };
                    }
                },
                .end_question, .end_answer, .end_nameserver, .end_additional => unreachable,
                .answer, .nameserver, .additional => {
                    const raw_resource = try dns.Resource.readFrom(self.reader, self.options);

                    const name = @tagName(self.state);
                    @field(self.ctx.current_counts.question, name) += 1;

                    if (@field(self.ctx.current_counts.question, name) > @field(self.ctx.header.?, name ++ "_length")) {
                        const old_state = self.state;
                        self.state = switch (self.state) {
                            .answer => .nameserver,
                            .nameserver => .additional,
                            .additional => null,
                        };

                        return switch (old_state) {
                            .answer => ParserFrame{ .end_answer = {} },
                            .nameserver => ParserFrame{ .end_nameserver = {} },
                            .additional => ParserFrame{ .end_additional = {} },
                            else => unreachable,
                        };
                    } else {
                        return switch (self.state) {
                            .answer => ParserFrame{ .answer = raw_resource },
                            .nameserver => ParserFrame{ .nameserver = raw_resource },
                            .additional => ParserFrame{ .additional = raw_resource },
                            else => unreachable,
                        };
                    }
                },
            } else {
                return null;
            }
        }
    };
}
