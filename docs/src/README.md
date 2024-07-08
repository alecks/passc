# Introduction

`passc` is a small CLI tool for storing passwords with demanding encryption, without storing any secret keys on disk. It depends upon [libsodium](https://doc.libsodium.org) for cryptography and [sqlite3](https://sqlite.org/index.html) for storage.

Jump to the [Usage](./usage.md) section for installation & setup.

### Relies on a master passphrase

`passc` will derive a `crypto_secretbox` key from a chosen master passphrase using `crypto_pwhash`. This will be used to encrypt passwords for one specific vault. This passphrase is never stored, and neither is the secret key; it is derived every time a password is encrypted/decrypted, which is an intensive process and prevents brute-forcing of the passphrase. Deriving a secret key from a passphrase takes around 3 seconds with an Apple M3 Pro chip.

One salt is used for every vault and stored in the `~/.passc` directory. This ensures every user derives a different secret key, even if they use the same passphrase. This salt is stored separate to the database to make it easy to back up.

### Passphrase is verified for sensitive operations

Even though this passphrase and secret key aren't stored, the secret key is hashed (`crypto_pwhash_str`) with a random salt upon creation and stored in the DB. This allows the passphrase to be verified to ensure all passwords in the same vault are encrypted with the same key.

This prevents a user adding a password to a vault with the incorrect passphrase, but does not stop an attacker deleting encrypted passwords manually from the SQLite DB. The salt and database should be backed up constantly.
