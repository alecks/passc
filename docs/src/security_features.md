# Security features

`passc` tries to keep plaintext passwords and secret keys in memory for as little time as possible. Deriving the secret key uses `crypto_pwhash_OPSLIMIT_MODERATE` and `crypto_pwhash_MEMLIMIT_MODERATE` by default, which requires 256MiB of RAM and takes around 2 seconds on an M3 Pro chip. This can be increased upon creation of a passphrase. To hash the secret key (used for verification), `INTERACTIVE` is used. This is much faster.

### sodium_mlock

Sensitive data in memory is locked using `sodium_mlock`. Some systems do not support this. Enabling verbose logging (`-V`) will show whether it is supported. This helps avoid swapping sensitive memory to disk. See [libsodium's secure memory docs](https://doc.libsodium.org/memory_management) for more information.

`sodium_memzero` is always called regardless of whether `sodium_mlock` fails, attempting to overwrite sensitive memory after use.

### Key rotation

Keys can be rotated using the `rotate` subcommand. This requests the current passphrase used for the vault, derives the vault's secret key, decrypts all passwords and re-encrypts them with a new passphrase. This can be used to change the hash parameters.
