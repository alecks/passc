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
    const ciphertext = try vault.encryptMessage(allocator, "passphrase", "my password");
    defer allocator.free(ciphertext);

    std.debug.print("ciphertext: {s}\n", .{ciphertext});

    const plaintext = try vault.decryptMessage(allocator, "passphrase", ciphertext);
    defer allocator.free(plaintext);

    std.debug.print("plaintext: {s}\n", .{plaintext});
}
