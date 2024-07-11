const std = @import("std");
const crypto = std.crypto;
const DB = @import("db.zig");

const Self = @This();

pub const Salt = [16]u8;

allocator: std.mem.Allocator,

name: []const u8,
salt: Salt = undefined,
keyhash: []u8 = undefined,
opslimit: i32,
memlimit: i32,
hashalg: i32,

pub fn deinit(self: Self) void {
    self.allocator.free(self.keyhash);
}

/// Gets a vault from the database. Errors if this query fails, otherwise returns null.
/// This can be used in conjunction with create, i.e. `try Vault.get(...) orelse try Vault.create(...)`
/// Must call deinit.
pub fn get(allocator: std.mem.Allocator, db: DB, name: []const u8) !?Self {
    return db.getVault(allocator, name);
}

/// Derives a key from a passphrase, hashes the key and generates a salt. Written to DB.
/// Must call deinit.
pub fn create(allocator: std.mem.Allocator, db: DB, name: []const u8, passphrase: []const u8) !Self {
    _ = db;
    _ = passphrase;

    const salt = generateSalt();

    return Self{
        .allocator = allocator,
        .name = name,
        .salt = salt,
        .opslimit = 0,
        .memlimit = 0,
        .hashalg = 0,
    };
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

/// Generates a new salt, 8 bytes in size, and returns it.
pub fn generateSalt() Salt {
    var salt: Salt = undefined;
    crypto.random.bytes(&salt);

    return salt;
}
