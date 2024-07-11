const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});
const Passc = @import("lib/root.zig");

pub fn main() !void {
    if (c.sodium_init() < 0) {
        std.log.err("sodium_init returned < 0\n", .{});
        return error.SodiumInitFailed;
    }

    const allocator = std.heap.c_allocator;

    var passc = try Passc.init(allocator, null);
    defer passc.deinit();

    try passc.db.getVault("test");
}
