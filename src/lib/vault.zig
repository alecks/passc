const std = @import("std");
const DB = @import("db.zig");

const Self = @This();

allocator: std.mem.Allocator,
name: []const u8,
salt: []const u8,
keyhash: []const u8,

/// Gets a vault from the database. Errors if this query fails, otherwise returns null. Application must call deinit.
/// This can be used in conjunction with create, i.e. `try Vault.get(...) orelse try Vault.create(...)`
pub fn get(alloc: std.mem.Allocator, db: DB, name: []const u8) !?Self {
    _ = alloc;
    _ = db;
    _ = name;
}

/// Derives a key from a passphrase, hashes the key and generates a salt. These are inserted into the DB.
/// The application must call deinit.
pub fn create(alloc: std.mem.Allocator, db: DB, name: []const u8, passphrase: []const u8) !Self {
    _ = alloc;
    _ = db;
    _ = name;
    _ = passphrase;
    // self.salt = generateSalt()...
}

pub fn deinit(self: Self) void {
    _ = self;
}

/// Derives a key from a passphrase, hashes said key, and verifies it against the keyhash.
pub fn verifyPassphrase(self: Self, passphrase: []const u8) void {
    _ = self;
    _ = passphrase;
}

/// Verifies a passphrase and encrypts a message, returning the ciphertext.
pub fn encryptMessage(self: Self, passphrase: []const u8, message: []const u8) void {
    _ = self;
    _ = passphrase;
    _ = message;
}

/// Verifies a passphrase and decrypts a ciphertext, returning the plaintext.
pub fn decryptMessage(self: Self, passphrase: []const u8, ciphertext: []const u8) void {
    _ = self;
    _ = passphrase;
    _ = ciphertext;
}
