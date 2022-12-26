const Builder = std.build.Builder;
const std = @import("std");
pub fn build(b: *Builder) void {
    const native_opt = b.option(bool, "native", "if many cpu, turn this on");
    const option_libc = (b.option(bool, "libc", "build with libc?")) orelse false;
    const is_native = native_opt orelse true;

    var target: std.zig.CrossTarget = undefined;
    if (is_native) {
        target = b.standardTargetOptions(.{});
    } else {
        // my friends amd cpu is an fx 6300 and it kind of didnt work so
        target = b.standardTargetOptions(.{
            .default_target = .{
                .cpu_model = .{ .explicit = &std.Target.x86.cpu.athlon_fx },
            },
        });
    }

    const mode = b.standardReleaseOptions();

    // this exports both a library and a binary

    // TODO separate exe entrypoint and lib entrypoint

    const exe = b.addExecutable("zigdig", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    if (option_libc) exe.linkLibC();

    const lib = b.addStaticLibrary("zigdig", "src/lib.zig");
    lib.setTarget(target);
    lib.setBuildMode(mode);

    var lib_tests = b.addTest("src/main.zig");
    lib_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib_tests.step);

    const run_cmd = exe.run();
    const run_step = b.step("run", "Run example binary");
    run_step.dependOn(&run_cmd.step);

    b.default_step.dependOn(&lib.step);
    b.default_step.dependOn(&exe.step);

    lib.addPackagePath("dns", "src/lib.zig");
    exe.addPackagePath("dns", "src/lib.zig");

    b.installArtifact(lib);
    b.installArtifact(exe);
}
