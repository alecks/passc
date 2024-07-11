const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "passc",
        .root_source_file = b.path("src/lib/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();

    lib.addIncludePath(std.Build.LazyPath{ .cwd_relative = "/opt/homebrew/include" });
    lib.addLibraryPath(std.Build.LazyPath{ .cwd_relative = "/opt/homebrew/lib" });
    lib.linkSystemLibrary("sodium");
    lib.linkSystemLibrary("sqlite3");

    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "passc-server",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibrary(lib);

    exe.linkLibC();
    // HACK: there must be a better way to do this. i almost died
    exe.addIncludePath(std.Build.LazyPath{ .cwd_relative = "/opt/homebrew/include" });
    exe.addLibraryPath(std.Build.LazyPath{ .cwd_relative = "/opt/homebrew/lib" });
    exe.linkSystemLibrary("sodium");
    exe.linkSystemLibrary("sqlite3");

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
