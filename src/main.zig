const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});
const Passc = @import("lib/root.zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    var passc = try Passc.init(allocator, null);
    defer passc.deinit();

    const vault = try Passc.Vault.get(allocator, passc.db, "test") orelse try Passc.Vault.create(allocator, passc.db, "test", "passphrase", .{});
    defer vault.deinit();

    std.debug.print("vault salt: {s}\nkeyhash: {s}\n", .{ vault.salt, vault.keyhash });

    const password = try vault.getPassword(allocator, 1) orelse try vault.addPassword("passphrase", "bread", "plaintext");
    defer password.deinit();

    std.debug.print("ref: {s}\n", .{password.ref});
}
