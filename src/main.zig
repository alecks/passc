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

    var vault = try Passc.Vault.get(allocator, passc.db, "test") orelse return;
    defer vault.deinit();
    std.debug.print("vault salt: {s}\nkeyhash: {s}\n", .{ vault.salt, vault.keyhash });

    // {
    //     const vault2 = try Passc.Vault.create(gpa, passc.db, "test", "sdhjflk");
    //     std.debug.print("vault salt: {s}\nkeyhash: \n", .{vault2.salt});
    // }

    // if (gpa_thing.detectLeaks()) {
    //     std.debug.print("LEAK\n", .{});
    // }
}
