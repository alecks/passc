#include "cwalk.h"
#include <errno.h>
#include <pwd.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define MIGRATION_QUERY                                                        \
  "PRAGMA foreign_keys = ON;"                                                  \
  "CREATE TABLE IF NOT EXISTS vaults"                                          \
  "(vname TEXT PRIMARY KEY, keyhash TEXT UNIQUE NOT NULL);"                    \
  "CREATE TABLE IF NOT EXISTS passwords ("                                     \
  "pname TEXT PRIMARY KEY,"                                                    \
  "ref TEXT NOT NULL,"                                                         \
  "ciphertext BLOB NOT NULL,"                                                  \
  "vname INTEGER NOT NULL,"                                                    \
  "FOREIGN KEY (vname) REFERENCES vaults (vname));"

void perr_usage(const char *pname) {
  fprintf(stderr,
          "Usage:\n"
          "  %s [-n vault_name] (add|rm|get) <password name>\n"
          "  %s [-n vault_name] ls\n"
          "\n"
          "Options:\n"
          "  -v Enable verbose logging.\n",
          pname, pname); // could use %n$, but this is a compiler warning
}

int _passc_log_level = 0;

// verbose format logging if _passc_log_level is >= 1
void verbosef(const char *format, ...) {
  if (_passc_log_level < 1)
    return;

  va_list args;

  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

// this does NOT retain \n. locks memory with sodium_mlock; callers
// responsibility to sodium_munlock and free. returns -1 on error, 0 on ok
ssize_t passc_getpassline(char **lineptr, size_t *n, FILE *stream) {
  struct termios old, new;
  int nread;

  if (tcgetattr(fileno(stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  // set our new flags
  if (tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
    return -1;

  nread = getline(lineptr, n, stream);
  if (nread > 0) {
    (*lineptr)[--nread] = '\0'; // replace \n
  }
  printf("\n");

  if (sodium_mlock(*lineptr, *n) != 0) {
    verbosef("v: sodium_mlock failed; your platform may not support this. "
             "error: %s\n",
             strerror(errno));
  }

  // restore to old
  tcsetattr(fileno(stream), TCSAFLUSH, &old);
  return nread;
}

// tries to get the homedir from passwd entry, otherwise $HOME, otherwise cwd.
// expects out to be able to fit PATH_MAX
void get_homedir(char *out) {
  const char *dir;
  struct passwd *pwd = getpwuid(getuid());
  if (pwd && pwd->pw_dir) {
    dir = pwd->pw_dir;
  } else {
    dir = getenv("HOME");
  }

  if (!dir) {
    dir = ".";
  }
  snprintf(out, PATH_MAX, "%s", dir);
}

int gen_new_salt(unsigned char *salt, size_t n, const char *filepath) {
  verbosef("v: making new random salt\n");
  randombytes_buf(salt, n);

  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    perror("gen_new_salt: couldn't open salt file for writing");
    return -1;
  }
  if (fwrite(salt, 1, n, fp) != n) {
    fclose(fp);
    fprintf(stderr, "gen_new_salt: unexpected num of bytes written\n");
    return -1;
  }

  fclose(fp);
  verbosef("v: new salt has been written at %s\n", filepath);
  return 0;
}

int find_salt(unsigned char *salt, size_t n) {
  char homedir[PATH_MAX];
  char filepath[PATH_MAX];

  get_homedir(homedir);
  cwk_path_join(homedir, ".passc/salt", filepath, sizeof(filepath));

  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    return gen_new_salt(salt, n, filepath);
  }

  size_t readlen = fread(salt, 1, n, fp);
  if (ferror(fp) != 0) {
    perror("find_salt: failed to read salt file");
    fclose(fp);
    return -1;
  } else if (readlen != n) {
    fprintf(stderr, "find_salt: read less bytes than required from salt file");
    fclose(fp);
    return -1;
  }

  fclose(fp);
  verbosef("v: using found salt file\n");
  return 1;
}

// wrapper over crypto_pwhash using the salt
int derive_key(unsigned char *out, size_t outlen, char *passwd,
               size_t passwdlen) {
  unsigned char salt[crypto_pwhash_SALTBYTES];
  if (find_salt(salt, sizeof(salt)) < 0) {
    return -1;
  }

  return crypto_pwhash(
      out, outlen, passwd, passwdlen, salt, crypto_pwhash_OPSLIMIT_MODERATE,
      crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT);
}

// wrapper over crypto_pwhash_str, casts unsigned char to char
int hash_derived_key(char *out, const unsigned char *const passwd,
                     size_t passwdlen) {
  return crypto_pwhash_str(out, (const char *const)passwd, passwdlen,
                           crypto_pwhash_OPSLIMIT_INTERACTIVE,
                           crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

// reads a passphrase from stdin and derives a key from it; 0 if ok, -1 on error
int derivekey_getpassline(unsigned char *key, size_t keysize) {
  char *passphrase = NULL;
  size_t psize = 0;

  printf("Enter passphrase for vault: ");
  ssize_t readlen = passc_getpassline(&passphrase, &psize, stdin);
  if (readlen == -1) {
    fprintf(stderr, "hash_getpassline: could not read passphrase from stdin\n");
    sodium_munlock(passphrase, psize);
    free(passphrase);
    return -1;
  }

  if (derive_key(key, keysize, passphrase, readlen) != 0) {
    fprintf(stderr, "hash_getpassline: failed to derive key, OOM?\n");
    sodium_munlock(passphrase, psize);
    free(passphrase);
    return -1;
  }

  sodium_munlock(passphrase, psize);
  free(passphrase);
  verbosef("v: key has been derived\n");
  return 0;
}

// same as derivekey_getpassline, except discards the key and returns the hash
// of the key instead. 0 if ok, -1 on error.
int keyhash_getpassline(char *outkeyhash) {
  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  if (derivekey_getpassline(key, sizeof(key)) < 0) {
    sodium_munlock(key, sizeof(key));
    return -1;
  }

  // we now have the key; hash this and store it so that, upon insertion into
  // the vault, we can check if it is the correct passphrase
  if (hash_derived_key(outkeyhash, key, sizeof(key)) != 0) {
    fprintf(stderr, "keyhash_getpassline: failed to hash derived key, OOM?\n");
    sodium_munlock(key, sizeof(key));
    return -1;
  }

  verbosef("v: derived key has been hashed\n");
  sodium_munlock(key, sizeof(key));
  return 0;
}

// migrates the database using MIGRATION_QUERY; returns 0 if ok, -1 on error
int db_migrate_up(sqlite3 *db) {
  char *errmsg = NULL;
  sqlite3_exec(db, MIGRATION_QUERY, NULL, NULL, &errmsg);

  if (errmsg) {
    fprintf(stderr, "db_migrate_up: failed to migrate db: %s\n", errmsg);
    sqlite3_free(errmsg);
    sqlite3_close(db);
    return -1;
  }

  verbosef("v: migrated db, no error\n");
  return 0;
}

// opens the db and migrates up. callers responsibility to run
// sqlite3_close, unless return value is <0.
int db_init(const char *filename, sqlite3 **outhdl) {
  sqlite3 *db;
  int rc = sqlite3_open_v2(filename, &db,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_init: failed to open sqlite3 db: %s\n",
            sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  *outhdl = db;
  verbosef("v: sqlite3 db opened\n");
  return db_migrate_up(db);
}

// creates a new vault. returns 0 if ok, -1 on error.
int db_vault_create(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;

  printf("KEY CREATION: A key will be derived from your given passphrase.\n"
         "Ensure this is different to those used by other vaults.\n");

  char keyhash[crypto_pwhash_STRBYTES];
  if (keyhash_getpassline(keyhash) < 0)
    return -1;

  char *queryt = sqlite3_mprintf(
      "INSERT INTO vaults (vname, keyhash) VALUES (%Q, %Q)", vname, keyhash);
  int rc = sqlite3_prepare(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_vault_create: could not prepare query: %s\n",
            sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  int retcode;
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    printf("Created new vault: %s\n", vname);
    retcode = 0;
  } else {
    fprintf(stderr, "db_vault_create: failed to advance query: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
  }

  sqlite3_finalize(stmt);
  return retcode;
}

// checks if a vault exists, creates if it doesn't. returns 1 if already exists,
// 0 on create, -1 on error.
int db_vault_init(sqlite3 *db, const char *vname) {
  int retcode = 0;

  sqlite3_stmt *stmt;
  char *queryt =
      sqlite3_mprintf("SELECT 1 FROM vaults WHERE vname = %Q", vname);
  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "could not prepare query: %s\n", sqlite3_errmsg(db));
    retcode = -1;
    goto cleanup;
  }

  switch (sqlite3_step(stmt)) {
  case SQLITE_DONE:
    printf("vault '%s' does not exist. creating...\n", vname);
    retcode = db_vault_create(db, vname);
    break;
  case SQLITE_ROW:
    verbosef("v: vault found, continuing\n");
    retcode = 1;
    break;
  default:
    fprintf(stderr, "db_vault_init: failed to advance query: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
  }

cleanup:
  sqlite3_finalize(stmt);
  return retcode;
}

// main function used for creating a db handle. runs db_init and
// db_vault_init. callers responsibility to sqlite3_close if 0 returned (ok)
int make_db(const char *vname, sqlite3 **outhdl) {
  sqlite3 *db;
  if (db_init("passc.db", &db) < 0)
    return -1;

  if (db_vault_init(db, vname) < 0) {
    sqlite3_close(db);
    return -1;
  }

  *outhdl = db;
  return 0;
}

// prints refs and pnames to stdout; returns 0 if ok, -1 on error
int subcmd_vault_list(const char *vname) {
  int retcode = 0;

  sqlite3 *db;
  if (make_db(vname, &db) < 0)
    return -1;

  sqlite3_stmt *stmt;
  char *queryt = sqlite3_mprintf(
      "SELECT pname, ref FROM passwords WHERE vname = %Q", vname);
  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "subcmd_vault_list: couldn't prepare query: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
    goto cleanup;
  }

  rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    int nocols = sqlite3_column_count(stmt);

    // could use strcat here, probably not worth it for now
    for (int i = 0; i < nocols; i++) {
      printf("%s ", sqlite3_column_text(stmt, i));
      if (i != nocols - 1) {
        printf("| ");
      }
    }
    printf("\n");

    rc = sqlite3_step(stmt);
  }

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "subcmd_vault_list: failed to advance query: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
  }

cleanup:
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return retcode;
}

// selects the keyhash from the db, used to verify passphrases. returns -1 on
// error, -2 if not found, 0 if ok
int db_get_keyhash(char *out, sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;
  char *queryt =
      sqlite3_mprintf("SELECT keyhash FROM vaults WHERE vname = %Q", vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_get_keyhash: failed to prepare query: %s\n",
            sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    fprintf(stderr, "db_get_keyhash: query for keyhash returned no rows\n");
    sqlite3_finalize(stmt);
    return -2;
  }

  strcpy(out, (const char *)sqlite3_column_text(stmt, 0));
  verbosef("v: found existing keyhash\n");

  sqlite3_finalize(stmt);
  return 0;
}

// subcommand to add a new password to a vault. returns 0 if ok, -1 on error, -2
// on invalid password.
int subcmd_vault_add(const char *vname) {
  sqlite3 *db;
  if (make_db(vname, &db) < 0)
    return -1;

  unsigned char key[crypto_secretbox_KEYBYTES];
  char dbhash[crypto_pwhash_STRBYTES];
  sodium_mlock(key, sizeof(key));

  if (derivekey_getpassline(key, sizeof(key)) < 0) {
    sodium_munlock(key, sizeof(key));
    sqlite3_close(db);
    return -1;
  }

  if (db_get_keyhash(dbhash, db, vname) < 0) {
    sodium_munlock(key, sizeof(key));
    sqlite3_close(db);
    return -1;
  }

  if (crypto_pwhash_str_verify(dbhash, (const char *const)key, sizeof(key)) !=
      0) {
    fprintf(stderr, "incorrect passphrase for '%s'\n", vname);

    sodium_munlock(key, sizeof(key));
    sqlite3_close(db);
    return -2;
  }

  printf("ok\n");
  // TODO: receive password, ref and pname, encrypt, insert
  return 0;
}

// runs mkdir for the homedir/.passc directory. uses get_homedir; cwd will be
// used instead if unavailable. -1 on error, 0 if ok
int passc_dirinit(void) {
  char pth[PATH_MAX];
  char homedir[PATH_MAX];

  get_homedir(homedir);
  cwk_path_join(homedir, ".passc", pth, sizeof(pth));

  errno = 0;
  if (mkdir(pth, 0777) != 0 && errno != EEXIST) {
    fprintf(stderr, "failed to create .passc directory at %s\n", pth);
    return -1;
  }
  verbosef("v: .passc dir available at %s\n", pth);
  return 0;
}

int main(int argc, char **argv) {
  char *pname = argv[0];
  if (sodium_init() < 0) {
    fprintf(stderr, "%s: sodium_init failed\n", pname);
    return EXIT_FAILURE;
  }

  const char *vault_name = NULL;

  // OPTION MATCHING
  int opt;
  while ((opt = getopt(argc, argv, "vn::")) != -1) {
    switch (opt) {
    case 'n':
      vault_name = optarg;
      break;
    case 'v':
      _passc_log_level = 1;
      break;
    default: // '?'
      perr_usage(pname);
      return EXIT_FAILURE;
    }
  }

  if (!vault_name)
    vault_name = "main";

  if (passc_dirinit() != 0)
    return EXIT_FAILURE;

  // SUBCOMMAND MATCHING
  if (optind >= argc) {
    fprintf(stderr, "%s: expected subcommand\n", pname);
    perr_usage(pname);
    return EXIT_FAILURE;
  }

  char *subcmd = argv[optind];
  if (strcmp(subcmd, "ls") == 0) {
    if (subcmd_vault_list(vault_name) < 0) {
      fprintf(stderr, "couldn't list passwords in vault '%s'\n", vault_name);
      return EXIT_FAILURE;
    }
  } else if (strcmp(subcmd, "add") == 0) {
    if (subcmd_vault_add(vault_name) < 0) {
      fprintf(stderr, "failed to add to vault\n");
    }
  } else {
    fprintf(stderr, "%s: unknown subcommand '%s'\n", pname, subcmd);
    perr_usage(pname);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
