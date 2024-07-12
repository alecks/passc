const std = @import("std");
const Vault = @import("vault.zig");

const Self = @This();

vault: Vault,

pub fn get(vault: Vault) !Self {
    return Self{
        .vault = vault,
    };
}

pub fn create(vault: Vault) !Self {
    return Self{
        .vault = vault,
    };
}
