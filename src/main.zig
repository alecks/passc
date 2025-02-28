const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});
const Passc = @import("lib/root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var passc = try Passc.init(allocator, null);
    defer passc.deinit();

    const vault = try Passc.Vault.get(allocator, passc.db, "test") orelse try Passc.Vault.create(allocator, passc.db, "test", "passphrase", .{});
    defer vault.destroy();

    std.debug.print("vault salt: {s}\nkeyhash: {s}\nnull term: {d}\n", .{ vault.salt, vault.keyhash, vault.keyhash[vault.keyhash.len] });

    var pw_arena = std.heap.ArenaAllocator.init(allocator);
    defer pw_arena.deinit();
    const pw_alloc = pw_arena.allocator();

    const password = try vault.getPassword(pw_alloc, 1) orelse try vault.addPassword(pw_alloc, "passphrase", "bread", "plaintext");

    std.debug.print("ref: {s}\n", .{password.ref});
}
