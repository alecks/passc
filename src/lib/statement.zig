const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});
const DB = @import("db.zig");
const DBError = DB.DBError;

const Self = @This();

db: DB,
_stmt: ?*c.sqlite3_stmt,

pub fn init(db: DB, statement_text: [:0]const u8) DBError!Self {
    var stmt: ?*c.sqlite3_stmt = undefined;
    if (c.sqlite3_prepare_v2(db._db, statement_text, -1, &stmt, null) != c.SQLITE_OK) {
        db._logSqliteError("PrepareError: Statement.init");
        return DBError.PrepareError;
    }

    return Self{ .db = db, ._stmt = stmt };
}

/// Finalizes the statement, freeing any return values from the column functions.
pub fn deinit(self: Self) void {
    _ = c.sqlite3_finalize(self._stmt);
}

/// Steps a statement, returning whether the result was SQLITE_ROW or SQLITE_DONE.
/// true if ROW, false if DONE.
pub fn step(self: Self) DBError!bool {
    const rc = c.sqlite3_step(self._stmt);

    if (rc != c.SQLITE_DONE and rc != c.SQLITE_ROW) {
        self.db._logSqliteError("StepError: sqlite didn't return ROW or DONE");
        return DBError.StepError;
    }

    return rc == c.SQLITE_ROW;
}

/// Reads the TEXT from the nth column, 0-indexed. SQLite casts this to a string if necessary.
/// Return value must not be used after calling deinit; SQLite manages this memory.
pub fn columnText(self: Self, n: i32) ?[]const u8 {
    const text = c.sqlite3_column_text(self._stmt, n);
    if (text) |t| {
        return std.mem.span(t);
    }
    return null;
}

/// Reads a BLOB from the nth column, 0-indexed. SQLite may cast this. Can't be used after
/// deinit, as SQLite manages the memory.
pub fn columnBlob(self: Self, n: i32) ?[]const u8 {
    const blob = c.sqlite3_column_blob(self._stmt, n);
    const blob_size = c.sqlite3_column_bytes(self._stmt, n);

    if (blob) |b| {
        // HACK: there must be a better way to do this
        // maybe just use std.mem.span with sqlite casting to text
        return @as([*]const u8, @ptrCast(b))[0..@intCast(blob_size)];
    }

    return null;
}

/// Reads an INTEGER from the nth column, 0-indexed. If the column is NULL, returns
/// null (unlike C interface which returns 0). Value may be used after deinit.
pub fn columnInt(self: Self, n: i32) ?i32 {
    const valtype = c.sqlite3_column_type(self._stmt, n);
    if (valtype == c.SQLITE_NULL) {
        return null;
    }

    return c.sqlite3_column_int(self._stmt, n);
}

pub fn columnInt64(self: Self, n: i32) ?i64 {
    const valtype = c.sqlite3_column_type(self._stmt, n);
    if (valtype == c.SQLITE_NULL) {
        return null;
    }

    return c.sqlite3_column_int64(self._stmt, n);
}

/// Binds TEXT to the nth SQL parameter, 0-indexed (unlike the C library).
pub fn bindText(self: Self, n: i32, text: [:0]const u8) !void {
    const rc = c.sqlite3_bind_text(self._stmt, n + 1, text, -1, null);
    if (rc != c.SQLITE_OK) {
        self.db._logSqliteError("BindError: bind_text didn't return OK");
        return DBError.BindError;
    }
}
