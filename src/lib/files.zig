const std = @import("std");
const log = std.log.scoped(.PasscFiles);

const Self = @This();

data_dir: []const u8 = ".passc",

/// Creates the entire file path for data_dir. Succeeds if already exists.
pub fn init(data_dir: ?[]const u8) !Self {
    var self = Self{};
    if (data_dir) |dir| {
        self.data_dir = dir;
    }

    try std.fs.cwd().makePath(self.data_dir);
    log.info("data directory available at {s}", .{self.data_dir});

    return self;
}

pub fn deinit(self: Self) void {
    _ = self;
}

/// For internal use by DB. Assumes this is only called once in dbOpen, so
/// this is not stored. Caller must free. Path is zero-terminated.
pub fn dbPath(self: Self, alloc: std.mem.Allocator) ![:0]const u8 {
    return std.fs.path.joinZ(alloc, &.{ self.data_dir, "db.sqlite3" });
}
