const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    // this exports both a library and a binary

    // TODO separate exe entrypoint and lib entrypoint

    const exe = b.addExecutable("dig", "src/main.zig");
    exe.setBuildMode(mode);

    const lib = b.addStaticLibrary("zigdig", "src/main.zig");
    lib.setBuildMode(mode);

    const names = [][]const u8{"packet"};

    const sources = [][]const u8{"src/packet.zig"};

    for (names) |name, idx| {
        // get name and source path
        var obj_step = b.addObject(name, sources[idx]);
        b.default_step.dependOn(&obj_step.step);
    }

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const run_cmd = exe.run();
    const run_step = b.step("run", "Run binary");
    run_step.dependOn(&run_cmd.step);

    b.default_step.dependOn(&lib.step);
    b.default_step.dependOn(&exe.step);

    b.installArtifact(lib);
    b.installArtifact(exe);
}
