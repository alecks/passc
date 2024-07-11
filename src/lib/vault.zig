const std = @import("std");
const crypto = std.crypto;
const c = @cImport({
    @cInclude("sodium.h");
});
const DB = @import("db.zig");

const Self = @This();

pub const Salt = [16]u8;
pub const VaultKey = [c.crypto_secretbox_KEYBYTES]u8;
pub const KeyHash = [c.crypto_pwhash_STRBYTES:0]u8;

pub const HashParameters = struct {
    opslimit: u64 = c.crypto_pwhash_OPSLIMIT_MODERATE,
    memlimit: usize = c.crypto_pwhash_MEMLIMIT_MODERATE,
    hashalg: i32 = c.crypto_pwhash_ALG_DEFAULT,

    keyhash_opslimit: u64 = c.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    keyhash_memlimit: usize = c.crypto_pwhash_MEMLIMIT_INTERACTIVE,
};

name: []const u8,
salt: Salt,
keyhash: KeyHash,
hash_parameters: HashParameters,

pub fn deinit(self: Self) void {
    _ = self;
}

/// Gets a vault from the database. Errors if this query fails, otherwise returns null.
/// This can be used in conjunction with create, i.e. `try Vault.get(...) orelse try Vault.create(...)`
pub fn get(db: DB, name: [:0]const u8) !?Self {
    return db.getVault(name);
}

/// Derives a key from a passphrase, hashes the key and generates a salt. Written to DB.
pub fn create(db: DB, name: []const u8, passphrase: [:0]const u8, hash_parameters: HashParameters) !Self {
    _ = db;

    var self = Self{
        .name = name,
        .salt = generateSalt(),
        .keyhash = undefined,
        .hash_parameters = hash_parameters,
    };

    const derived_key = try self.deriveKey(passphrase);
    self.keyhash = try self.hashKey(derived_key);

    // TODO: insert into db

    return self;
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

/// Derives a key for the Vault using the given passphrase. Uses hash_parameters.
fn deriveKey(self: Self, passphrase: [:0]const u8) !VaultKey {
    var derived_key: VaultKey = undefined;

    const rc = c.crypto_pwhash(derived_key[0..], derived_key.len, passphrase, passphrase.len, self.salt[0..], self.hash_parameters.opslimit, self.hash_parameters.memlimit, self.hash_parameters.hashalg);
    if (rc != 0) {
        return error.SodiumError;
    }

    return derived_key;
}

/// Hashes the given derived key for the Vault. Uses hash_parameters.keyhash_...
fn hashKey(self: Self, key: VaultKey) !KeyHash {
    var hash: KeyHash = undefined;

    const rc = c.crypto_pwhash_str(&hash, key[0..], key.len, self.hash_parameters.keyhash_opslimit, self.hash_parameters.keyhash_memlimit);
    if (rc != 0) {
        return error.SodiumError;
    }

    return hash;
}

/// Generates a new 16-byte salt.
fn generateSalt() Salt {
    var salt: Salt = undefined;
    crypto.random.bytes(&salt);

    return salt;
}
