const std = @import("std");
const dns = @import("lib.zig");

const logger = std.log.scoped(.dns_parser);

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
    answer,
    nameserver,
    additional,
    answer_rdata,
    nameserver_rdata,
    additional_rdata,
    done,
};

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
        var opaque_rdata = try allocator.alloc(u8, self.size);
        const read_bytes = try reader.read(opaque_rdata);
        std.debug.assert(read_bytes == opaque_rdata.len);
        return .{
            .data = opaque_rdata,
            .current_byte_count = self.current_byte_index,
        };
    }
};

pub const ParserOptions = struct {
    /// Give an allocator if you want names to appear properly.
    allocator: ?std.mem.Allocator = null,

    max_label_size: usize = 32,
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
        state: ParserState = .header,
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
            switch (self.state) {
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
                        return ParserFrame{ .end_question = {} };
                    } else {
                        return ParserFrame{ .question = raw_question };
                    }
                },
                .answer, .nameserver, .additional => {
                    const raw_resource = try dns.Resource.readFrom(self.reader, self.options);

                    var count_holder = (switch (self.state) {
                        .answer => &self.ctx.current_counts.answer,
                        .nameserver => &self.ctx.current_counts.nameserver,
                        .additional => &self.ctx.current_counts.additional,
                        else => unreachable,
                    });
                    count_holder.* += 1;

                    const header_count = switch (self.state) {
                        .answer => self.ctx.header.?.answer_length,
                        .nameserver => self.ctx.header.?.nameserver_length,
                        .additional => self.ctx.header.?.additional_length,
                        else => unreachable,
                    };

                    if (count_holder.* > header_count) {
                        const old_state = self.state;
                        self.state = switch (self.state) {
                            .answer => .nameserver,
                            .nameserver => .additional,
                            .additional => .done,
                            else => unreachable,
                        };

                        return switch (old_state) {
                            .answer => ParserFrame{ .end_answer = {} },
                            .nameserver => ParserFrame{ .end_nameserver = {} },
                            .additional => ParserFrame{ .end_additional = {} },
                            else => unreachable,
                        };
                    } else {
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

                    const rdata_length = try self.reader.readIntBig(u16);
                    const rdata_index = self.reader.context.ctx.current_byte_count;
                    var rdata = ResourceDataHolder{
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
