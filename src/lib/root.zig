pub const Vault = @import("vault.zig");

const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});
const DB = @import("db.zig");
const Files = @import("files.zig");

const Self = @This();

files: Files,
db: DB,

pub fn init(alloc: std.mem.Allocator, data_dir: ?[]const u8) !Self {
    if (c.sodium_init() < 0) {
        return error.SodiumInitFailed;
    }

    const files = try Files.init(data_dir);
    const db = try DB.init(alloc, files);

    return Self{ .files = files, .db = db };
}

pub fn deinit(self: Self) void {
    std.log.info("deiniting Passc", .{});
    self.db.deinit();
    self.files.deinit();
}
