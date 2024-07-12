const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});
const Files = @import("files.zig");
const Vault = @import("vault.zig");
const Password = Vault.Password;
const Statement = @import("statement.zig");
const log = std.log.scoped(.PasscDB);

const Self = @This();

pub const DBError = error{ OpenError, ExecError, PrepareError, StepError, BindError, UnexpectedLength };

_db: ?*c.sqlite3 = undefined,
allocator: std.mem.Allocator,
files: Files,

/// Opens and migrates the database. You must call deinit when finished.
pub fn init(alloc: std.mem.Allocator, files: Files) !Self {
    var self = Self{ .allocator = alloc, .files = files };

    try self.open();
    try self.migrate();

    return self;
}

/// Closes the database.
pub fn deinit(self: Self) void {
    log.debug("deiniting database", .{});
    self.close();
}

/// Gets a single vault by name. allocator is passed down to the returned Vault.
/// The caller must deinit the returned Vault.
pub fn selectVault(self: Self, allocator: std.mem.Allocator, vault_name: [:0]const u8) !?Vault {
    const stmt = try self.query("SELECT salt, keyhash, opslimit, memlimit, hashalg FROM vaults WHERE vname = ?");
    defer stmt.deinit();

    try stmt.bindText(0, vault_name);
    const row_available = try stmt.step();

    if (!row_available) {
        return null;
    }

    // these are all NOT NULL columns.
    const salt = stmt.columnBlob(0).?;
    if (salt.len != @sizeOf(Vault.Salt)) {
        log.err("UnexpectedLength: expected salt to be {d} bytes, got {d}", .{ @sizeOf(Vault.Salt), salt.len });
        return DBError.UnexpectedLength;
    }

    const keyhash = stmt.columnText(1).?;
    if (keyhash.len > Vault.PWHASH_STRBYTES) {
        log.err("UnexpectedLength: expected keyhash to <= {d} bytes, got {d}", .{ Vault.PWHASH_STRBYTES, keyhash.len });
        return DBError.UnexpectedLength;
    }

    const opslimit = stmt.columnInt64(2).?;
    const memlimit = stmt.columnInt64(3).?;
    const hashalg = stmt.columnInt(4).?;

    var vault = Vault{
        .allocator = allocator,
        .db = self,

        .name = vault_name,
        .salt = undefined,
        .keyhash = @ptrCast(try allocator.alloc(u8, keyhash.len)), // stmt.columnText is always null terminated
        .hash_parameters = .{
            .opslimit = @intCast(opslimit),
            .memlimit = @intCast(memlimit),
            .hashalg = hashalg,
        },
    };

    @memcpy(&vault.salt, salt);
    @memcpy(vault.keyhash, keyhash);

    return vault;
}

/// Inserts a new vault into the database, using INSERT, uniquely indexed by the vname.
pub fn insertVault(self: Self, vault: Vault) !void {
    const stmt = try self.query("INSERT INTO vaults (vname, salt, keyhash, opslimit, memlimit, hashalg) VALUES (?,?,?,?,?,?)");
    defer stmt.deinit();

    try stmt.bindText(0, vault.name);
    try stmt.bindBlob(1, &vault.salt);
    try stmt.bindText(2, vault.keyhash);
    try stmt.bindInt64(3, @intCast(vault.hash_parameters.opslimit));
    try stmt.bindInt64(4, @intCast(vault.hash_parameters.memlimit));
    try stmt.bindInt(5, vault.hash_parameters.hashalg);

    _ = try stmt.step();
}

pub fn insertPassword(self: Self, vault_name: [:0]const u8, ref: [:0]const u8, ciphertext: []const u8) !i64 {
    const stmt = try self.query("INSERT INTO passwords (ref, ciphertext, vname) VALUES (?,?,?)");
    defer stmt.deinit();

    try stmt.bindText(0, ref);
    try stmt.bindBlob(1, ciphertext);
    try stmt.bindText(2, vault_name);

    _ = try stmt.step();

    return self.getLastRowID();
}

pub fn selectPassword(self: Self, child_alloc: std.mem.Allocator, vault: Vault, id: i64) !?Password {
    const stmt = try self.query("SELECT ref, ciphertext FROM passwords WHERE pwid = ? AND vname = ?");
    try stmt.bindInt64(0, id);
    try stmt.bindText(1, vault.name);

    const row_available = try stmt.step();
    if (!row_available) {
        return null;
    }

    var arena_allocator = std.heap.ArenaAllocator.init(child_alloc);
    const allocator = arena_allocator.allocator();

    const ref = stmt.columnText(0).?;
    const ref_copy = try allocator.alloc(u8, ref.len);
    @memcpy(ref_copy, ref);

    const ciphertext = stmt.columnBlob(1).?;
    const ciphertext_copy = try allocator.alloc(u8, ciphertext.len);
    @memcpy(ciphertext_copy, ciphertext);

    return Password{
        .id = id,
        .vault = vault,
        .allocator = arena_allocator,
        .ref = @ptrCast(ref_copy),
        .ciphertext = @ptrCast(ciphertext_copy),
    };
}

/// Opens the database, using the path from the Files struct.
/// If this fails, close must be called.
fn open(self: *Self) !void {
    const db_path = try self.files.dbPath(self.allocator);
    defer self.allocator.free(db_path);

    if (c.SQLITE_OK != c.sqlite3_open_v2(db_path, &self._db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null)) {
        return DBError.OpenError;
    }

    log.debug("using sqlite3 version {s}", .{c.sqlite3_libversion()});
}

/// Calls sqlite3_close. This should not be used directly -- use deinit.
fn close(self: Self) void {
    _ = c.sqlite3_close(self._db);
}

// Executes a SQL statement, where the result is not needed. Returns DBError.ExecError
// if there is an error, otherwise nothing.
fn exec(self: Self, statements: [:0]const u8) DBError!void {
    var err_message: [*c]u8 = undefined;
    errdefer c.sqlite3_free(err_message);

    _ = c.sqlite3_exec(self._db, statements, null, null, &err_message);

    if (err_message) |e| {
        log.err("ExecError: {s}", .{e});
        return DBError.ExecError;
    }
}

// Returns a new Statement. Caller must deinit.
fn query(self: Self, statement: [:0]const u8) DBError!Statement {
    return Statement.init(self, statement);
}

/// Migrates the DB up. Migrations should be simple and use IF NOT EXISTS to avoid errors.
fn migrate(self: Self) DBError!void {
    const migration_stmt =
        \\PRAGMA foreign_keys = ON;
        \\CREATE TABLE IF NOT EXISTS vaults (
        \\  vname TEXT PRIMARY KEY,
        \\  salt BLOB NOT NULL,
        \\  keyhash TEXT UNIQUE NOT NULL,
        \\  memlimit INTEGER NOT NULL,
        \\  opslimit INTEGER NOT NULL,
        \\  hashalg INTEGER NOT NULL
        \\);
        \\CREATE TABLE IF NOT EXISTS passwords (
        \\  pwid INTEGER PRIMARY KEY,
        \\  ref TEXT NOT NULL,
        \\  ciphertext BLOB NOT NULL,
        \\  vname INTEGER NOT NULL,
        \\  FOREIGN KEY (vname) REFERENCES vaults (vname)
        \\);
        \\CREATE INDEX IF NOT EXISTS ref_idx ON passwords (ref);
    ;

    try self.exec(migration_stmt);
    log.info("migrations succeeded with no errors", .{});
}

/// Gets the last error code thrown by SQLite. Must be called directly after SQLite returns an error.
pub fn getLastErrorCode(self: Self) i32 {
    return c.sqlite3_errcode(self._db);
}

/// Gets the last INSERT's row ID. Must be called directly after insertion.
pub fn getLastRowID(self: Self) i64 {
    return c.sqlite3_last_insert_rowid(self._db);
}

/// Logs an error returned by sqlite (usually when a func returns non-SQLITE_OK, SQLITE_ROW, SQLITE_DONE).
/// Uses sqlite3_errmsg. This must be called directly after sqlite returns an error.
pub fn _logSqliteError(self: Self, message: []const u8) void {
    log.err("{s}: {s}", .{ message, c.sqlite3_errmsg(self._db) });
}
