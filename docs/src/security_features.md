# Security features

`passc` tries to keep plaintext passwords and secret keys in memory for as little time as possible. Deriving the secret key uses `crypto_pwhash_OPSLIMIT_MODERATE` and `crypto_pwhash_MEMLIMIT_MODERATE`, which requires 256MiB of RAM. This can be increased in the source code to be `SENSITIVE`, which takes much longer and requires 1024MiB of RAM. To hash the secret key (used for verification), `INTERACTIVE` is used. This is much faster.

### `sodium_mlock`

Sensitive data in memory is locked using `sodium_mlock`. Some systems do not support this. Enabling verbose logging (`-v`) will show whether it is supported. This helps avoid swapping sensitive memory to disk. See [libsodium's secure memory docs](https://doc.libsodium.org/memory_management) for more information.

`sodium_memzero` is always called regardless of whether `sodium_mlock` fails, attempting to overwrite sensitive memory after use.
