const std = @import("std");
const crypto = std.crypto;
const c = @cImport({
    @cInclude("sodium.h");
});
const DB = @import("db.zig");

const Vault = @This();

pub const SECRETBOX_KEYBYTES = c.crypto_secretbox_KEYBYTES;
pub const PWHASH_STRBYTES = c.crypto_pwhash_STRBYTES;
pub const SECRETBOX_MACBYTES = c.crypto_secretbox_MACBYTES;
pub const SECRETBOX_NONCEBYTES = c.crypto_secretbox_NONCEBYTES;

pub const Salt = [16]u8;
pub const Nonce = [c.crypto_secretbox_NONCEBYTES]u8;
pub const VaultKey = [c.crypto_secretbox_KEYBYTES]u8;
pub const KeyHash = [:0]u8;

allocator: std.mem.Allocator,
db: DB,

name: [:0]const u8,
salt: Salt,
keyhash: KeyHash,
hash_parameters: HashParameters,

pub fn deinit(self: Vault) void {
    self.allocator.free(self.keyhash);
}

/// Gets a vault from the database. Errors if this query fails, otherwise returns null.
/// This can be used in conjunction with create, i.e. `try Vault.get(...) orelse try Vault.create(...)`
pub fn get(allocator: std.mem.Allocator, db: DB, name: [:0]const u8) !?Vault {
    return db.selectVault(allocator, name);
}

/// Derives a key from a passphrase, hashes the key and generates a salt. Written to DB.
pub fn create(allocator: std.mem.Allocator, db: DB, name: [:0]const u8, passphrase: [:0]const u8, hash_parameters: HashParameters) !Vault {
    try hash_parameters.validate();
    var self = Vault{
        .allocator = allocator,
        .db = db,

        .name = name,
        .salt = generateSalt(),
        .keyhash = undefined,
        .hash_parameters = hash_parameters,
    };

    const derived_key = try self.deriveKey(passphrase);
    self.keyhash = try self.hashKey(allocator, derived_key);

    try db.insertVault(self);
    return self;
}

/// Derives a key from a passphrase, hashes said key, and verifies it against the keyhash.
/// Returns the derived key or error.IncorrectPassphrase.
pub fn verifyPassphrase(self: Vault, passphrase: [:0]const u8) !VaultKey {
    const derived_key = try self.deriveKey(passphrase);
    if (!self.compareKeyHash(derived_key)) {
        return error.IncorrectPassphrase;
    }

    return derived_key;
}

/// Adds a Password to the database, encrypting the plaintext with passphrase. Verifies passphrase.
pub fn addPassword(self: Vault, passphrase: [:0]const u8, ref: [:0]const u8, plaintext: [:0]const u8) !Password {
    const ciphertext = try self.encryptMessage(self.allocator, passphrase, plaintext);

    const id = try self.db.insertPassword(self.name, ref, ciphertext);
    return Password{
        .allocator = std.heap.ArenaAllocator.init(self.allocator),
        .vault = self,

        .id = id,
        .ref = @constCast(ref),
        .ciphertext = @constCast(ciphertext),
    };
}

/// Gets an encrypted Password by ID from the database. Can be decrypted with Password.decrypt.
/// Must call deinit on the returned Password.
pub fn getPassword(self: Vault, allocator: std.mem.Allocator, id: i64) !?Password {
    return self.db.selectPassword(allocator, self, id);
}

/// Lists all passwords in the Vault. Result length will be <= limit. Start from previous limit
/// for offset to get next set of passwords.
pub fn getPasswords(self: Vault, limit: i32, offset: i32) ![]const Password {
    _ = self;
    _ = limit;
    _ = offset;
}

/// Lists all passwords with a reference LIKE %ref% in the Vault.
pub fn getPasswordsByRef(self: Vault, ref: [:0]const u8) ![]const Password {
    _ = self;
    _ = ref;
}

/// Verifies a passphrase and encrypts a message, returning the combined ciphertext.
/// ct[0..NONCE_BYTES] is nonce, ct[NONCE_BYTES..] is ciphertext.
/// Must free result.
pub fn encryptMessage(self: Vault, allocator: std.mem.Allocator, passphrase: [:0]const u8, message: [:0]const u8) ![]const u8 {
    const key = try self.verifyPassphrase(passphrase);

    const nonce = generateNonce();
    const ciphertext = try self.allocator.alloc(u8, c.crypto_secretbox_MACBYTES + message.len);
    defer self.allocator.free(ciphertext);

    // cast here because sodium infers size of macbytes+msglen
    const rc = c.crypto_secretbox_easy(@ptrCast(ciphertext), message, message.len, &nonce, &key);
    if (rc != 0) {
        return error.SodiumError;
    }

    return std.mem.concat(allocator, u8, &.{ &nonce, ciphertext });
}

/// Decrypts a combined ciphertext without verifying the passphrase. Returns plaintext.
/// Must free result.
pub fn decryptMessage(self: Vault, allocator: std.mem.Allocator, passphrase: [:0]const u8, combined_ct: []const u8) ![]const u8 {
    const key = try self.deriveKey(passphrase);

    const nonce = combined_ct[0..SECRETBOX_NONCEBYTES];
    const ciphertext = combined_ct[SECRETBOX_NONCEBYTES..];
    const plaintext = try allocator.alloc(u8, ciphertext.len - SECRETBOX_MACBYTES);

    const rc = c.crypto_secretbox_open_easy(@ptrCast(plaintext), ciphertext.ptr, ciphertext.len, nonce, &key);
    if (rc != 0) {
        return error.DecryptError;
    }

    return plaintext;
}

/// Derives a key for the Vault using the given passphrase. Uses hash_parameters.
fn deriveKey(self: Vault, passphrase: [:0]const u8) !VaultKey {
    var derived_key: VaultKey = undefined;

    const rc = c.crypto_pwhash(&derived_key, derived_key.len, passphrase, passphrase.len, &self.salt, self.hash_parameters.opslimit, self.hash_parameters.memlimit, self.hash_parameters.hashalg);
    if (rc != 0) {
        return error.SodiumError;
    }

    return derived_key;
}

/// Hashes the given derived key for the Vault. Uses hash_parameters.keyhash_...
fn hashKey(self: Vault, allocator: std.mem.Allocator, key: VaultKey) !KeyHash {
    const hash = try allocator.alloc(u8, PWHASH_STRBYTES);

    // writes a null terminated string
    const rc = c.crypto_pwhash_str(hash.ptr, &key, key.len, self.hash_parameters.keyhash_opslimit, self.hash_parameters.keyhash_memlimit);
    if (rc != 0) {
        return error.SodiumError;
    }

    // see libsodium docs: https://libsodium.gitbook.io/doc/password_hashing/default_phf#password-storage
    // hash will always be null terminated
    return @ptrCast(hash);
}

/// Verifies a key against the Vault's keyhash.
fn compareKeyHash(self: Vault, key: VaultKey) bool {
    const rc = c.crypto_pwhash_str_verify(self.keyhash, &key, SECRETBOX_KEYBYTES);
    return rc == 0;
}

/// Generates a new 16-byte salt.
fn generateSalt() Salt {
    var salt: Salt = undefined;
    crypto.random.bytes(&salt);

    return salt;
}

fn generateNonce() Nonce {
    var nonce: Nonce = undefined;
    crypto.random.bytes(&nonce);

    return nonce;
}

/// Params required by libsodium to derive and hash keys.
pub const HashParameters = struct {
    opslimit: u64 = c.crypto_pwhash_OPSLIMIT_MODERATE,
    memlimit: usize = c.crypto_pwhash_MEMLIMIT_MODERATE,
    hashalg: i32 = c.crypto_pwhash_ALG_DEFAULT,

    keyhash_opslimit: u64 = c.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    keyhash_memlimit: usize = c.crypto_pwhash_MEMLIMIT_INTERACTIVE,

    // Validates hash parameters, returning an error if they are not within sodium's bounds.
    fn validate(params: HashParameters) HashParametersError!void {
        if (params.opslimit < c.crypto_pwhash_OPSLIMIT_MIN or params.opslimit > c.crypto_pwhash_OPSLIMIT_MAX) {
            return HashParametersError.OpsLimitOutOfBounds;
        }

        if (params.memlimit < c.crypto_pwhash_MEMLIMIT_MIN or params.memlimit > c.crypto_pwhash_MEMLIMIT_MAX) {
            return HashParametersError.MemLimitOutOfBounds;
        }

        if (params.hashalg != c.crypto_pwhash_ALG_ARGON2ID13 and params.hashalg != c.crypto_pwhash_ALG_ARGON2I13) {
            return HashParametersError.InvalidAlg;
        }

        if (params.keyhash_opslimit < c.crypto_pwhash_OPSLIMIT_MIN or params.keyhash_opslimit > c.crypto_pwhash_OPSLIMIT_MAX) {
            return HashParametersError.OpsLimitOutOfBounds;
        }

        if (params.keyhash_memlimit < c.crypto_pwhash_MEMLIMIT_MIN or params.keyhash_memlimit > c.crypto_pwhash_MEMLIMIT_MAX) {
            return HashParametersError.MemLimitOutOfBounds;
        }
    }
};

pub const HashParametersError = error{ OpsLimitOutOfBounds, MemLimitOutOfBounds, InvalidAlg };

pub const Password = struct {
    allocator: std.heap.ArenaAllocator,
    vault: Vault,

    id: i64,
    ref: [:0]u8,
    ciphertext: []u8,

    pub fn deinit(self: Password) void {
        self.allocator.deinit();
    }
};
