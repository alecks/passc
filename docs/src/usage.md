# Usage

You can use a pre-built binary or compile `passc` from source. It is currently known to support Linux and macOS systems. Pre-built binaries are available from the [Actions](https://github.com/alecks/passc/actions) page; select the latest build and scroll to the bottom.

If you choose to compile it yourself, you must have SQLite3 installed on your system. Clone the repository and run `cmake -B build && cmake --build build`. The resulting binary will be at `build/passc`.

## Creating a vault

A vault is a place with a unique passphrase used to store passwords. To create a new vault, run any subcommand; in this case we will run the `ls` command.

```
$ passc ls
```

This will create a new vault, 'main', and ask you to specify a passphrase. It will list nothing as there are not yet any passwords in the vault.

To use a different vault, use the `-v` flag, like so:

```
$ passc -vMyVault ls
```

This flag can be used in all of the subcommands below, otherwise defaulting to 'main'. `passc` uses GCC-style flags, so spaces are not allowed: `-vVault` is correct.

## Adding a password

Passwords are identified by their 'reference', like `example.org`, and a password ID (PWID). This is generated automatically when you add a password.

Run the following command to add a password for `github.com` in the 'main' vault:

```
$ passc add github.com
Enter passphrase for vault:
ok
Password for 'github.com':
Done. Password ID: 1
```

There is now a password with reference `github.com` and PWID `1` encrypted with the secret key for vault `main`.

## Getting a password

To retrieve and decrypt a password, use the `get` subcommand, for example:

```
$ passc get github.com
1 | github.com
Enter passphrase for vault:
```

This will list the passwords in the vault with a reference that contains 'github.com'. If there is only one match, it will be selected. If not, you will be asked to specify which password using the PWID, for example:

```
$ passc get example
2 | example.org
3 | example.org
4 | example.com
Select password:
```

This will search the vault for passwords with a reference like `example`. Enter the PWID, e.g. `2`, to select the first password for `example.org`.

You will then be prompted for the passphrase, and the password will be decrypted.

## Listing passwords in a vault

The PWIDs and references of all passwords in a vault can be listed without the passphrase. As shown earlier, you can use the `ls` subcommand:

```
$ passc ls
1 | github.com
2 | example.org
3 | example.org
4 | google.com
```

This will list all passwords in the 'main' vault.

## Deleting a password

The `rm` subcommand is used to delete passwords. Note that this asks for a passphrase, but this can provide a false sense of security -- anyone can delete passwords from the database manually if they have access to it.

This command works similarly to the `get` command:

```
$ passc rm github
1 | github.com
Deleting password with PWID 1. If you are unsure which password this is, use the 'get' subcommand to decrypt it before deletion.
Enter passphrase for vault:
```

This password will then be deleted.

## Recovering from a passphrase leak

If your passphrase has been leaked (but not your derived secret key), it is possible to retain a minimal form of security by ensuring the `~/.passc/salt` file is not accessible. This salt is mixed in with your passphrase when deriving your secret key. (see [todos](./todos.md) for `rotate` subcommand)
