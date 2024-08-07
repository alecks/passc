# Usage

You can use a pre-built binary or compile `passc` from source. It is currently known to support Linux and macOS systems. Pre-built binaries are available from the [Actions](https://github.com/alecks/passc/actions) page; select the latest build and scroll to the bottom.

If you choose to compile it yourself, you must have SQLite3 installed on your system. Clone the repository and run `cmake -B build && cmake --build build`. The resulting binary will be at `build/passc`.

## Creating a vault

A vault is a place with a unique passphrase used to store passwords. To create a new vault, run any subcommand; in this case we will run the `ls` command.

```
$ passc ls
vault 'main' does not exist. creating...

KEY CREATION: A key will be derived from your given passphrase.
Ensure this is different to those used by other vaults.

OPSLIMIT (moderate):
MEMLIMIT (moderate):

Enter passphrase for vault:
```

> It is highly recommended to skip past the OPSLIMIT and MEMLIMIT questions; these will default to `moderate` if you do not provide a value. Otherwise, it expects an integer. The default parameters require 256MiB of RAM and take about 2 seconds to derive a key with an M3 Pro chip. If you really require your passphrase to be harder to brute-force or have limited RAM, you can increase or decrease these values. See the [libsodium docs](https://doc.libsodium.org/password_hashing/default_phf#guidelines-for-choosing-the-parameters) for more information.

This will create a new vault, 'main', and ask you to specify a passphrase. It will list nothing as there are not yet any passwords in the vault.

To use a different vault name, use the `-v` flag, like so:

```
$ passc -vMyVault <subcommand>
```

This flag can be used in all of the subcommands below, otherwise defaulting to 'main'. `passc` uses GCC-style flags, so spaces are not allowed: `-vVault` is correct.

## Adding a password

Passwords are identified by their 'reference', like `example.org`, and a password ID (PWID). This is generated automatically when you add a password.

Run the following command to add a password for `github.com` in the 'main' vault:

```
$ passc add github.com

Enter passphrase for vault:
OK

Password for 'github.com':

1
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

## Changing a vault's passphrase

You can rotate the secret key used for a vault with the `rotate` command. This requires the current passphrase; it decrypts all passwords and re-encrypts them with a new key. The hash parameters can also be changed in this way.

For example, to change the passphrase of vault 'main':

```
$ passc rotate

KEY ROTATION: You will be prompted for new vault parameters, then you will be prompted for the current passphrase of vault 'main'. You can then specify a new passphrase for the vault, which will use the parameters specified initially.

OPSLIMIT (moderate):
MEMLIMIT (moderate):
Current --
Enter passphrase for vault:
OK

New --
Enter passphase for vault:
Vault key has been rotated. New keyhash: ...
```

> It is recommended not to change the OPSLIMIT and MEMLIMIT parameters. See [creating a vault](#creating-a-vault) for more info.
