# Introduction

`passc` is a small CLI tool for storing passwords with demanding encryption, without storing any secret keys on disk. It depends upon [libsodium](https://doc.libsodium.org) for encryption and [sqlite3](https://sqlite.org/index.html) for storage.

Jump to the [Usage](./usage.md) section for installation & setup.

### Relies on a master passphrase

`passc` will derive a secret key from a chosen master passphrase. This will be used to encrypt passwords for one specific vault (default 'main'). This passphrase is never stored, and neither is the secret key; it is created every time a password is encrypted/decrypted, which is an intensive process and prevents brute-forcing of the passphrase. Deriving a secret key from a passphrase takes around 3 seconds with an Apple M3 Pro chip.

One salt is used for every vault and stored in the `~/.passc` directory. This ensures every user derives a different secret key, even if they use the same passphrase. This salt is stored separate to the database to make it easy to back up.

### Passphrase is verified for sensitive operations

Even though this passphrase and secret key aren't stored, the secret key is hashed with a random salt upon creation and stored in the DB. This allows the passphrase to be verified to ensure all passwords in the same vault are encrypted with the same key.

This prevents a password being added to a vault without knowing its passphrase, and means it is impossible for an attacker to read a password without the master passphrase, but does not prevent an attacker from deleting encrypted passwords.
