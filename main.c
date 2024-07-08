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
  "CREATE TABLE IF NOT EXISTS vaults ("                                        \
  "vname TEXT PRIMARY KEY,"                                                    \
  "keyhash TEXT UNIQUE,"                                                       \
  "memlimit INTEGER NOT NULL,"                                                 \
  "opslimit INTEGER NOT NULL,"                                                 \
  "alg INTEGER NOT NULL);"                                                     \
                                                                               \
  "CREATE TABLE IF NOT EXISTS passwords ("                                     \
  "pwid INTEGER PRIMARY KEY,"                                                  \
  "ref TEXT NOT NULL,"                                                         \
  "ciphertext BLOB NOT NULL,"                                                  \
  "nonce BLOB NOT NULL,"                                                       \
  "vname INTEGER NOT NULL,"                                                    \
  "FOREIGN KEY (vname) REFERENCES vaults (vname));"                            \
                                                                               \
  "CREATE INDEX IF NOT EXISTS refidx ON passwords (ref);"

// tries to get the homedir from passwd entry, otherwise $HOME, otherwise cwd.
// expects out to be able to fit PATH_MAX
void get_homedir(char *out) {
  const char *dir = NULL;
  struct passwd *pwd = getpwuid(getuid());
  if (pwd && pwd->pw_dir) {
    dir = pwd->pw_dir;
  } else {
    dir = getenv("HOME");
  }

  if (!dir) {
    dir = ".";
  }
  strcpy(out, dir);
}

// runs mkdir for the ~/.passc and .passc/salts dirs. uses get_homedir; cwd will
// be used instead if unavailable. -1 on error, 0 if ok
int passc_dirinit(char *out) {
  char passcpath[PATH_MAX];
  char saltspath[PATH_MAX];
  char homedir[PATH_MAX];

  get_homedir(homedir);
  cwk_path_join(homedir, ".passc", passcpath, sizeof(passcpath));

  errno = 0;
  if (mkdir(passcpath, 0777) != 0 && errno != EEXIST) {
    fprintf(stderr, "failed to create .passc directory at %s\n", passcpath);
    return -1;
  }

  cwk_path_join(passcpath, "salts", saltspath, sizeof(saltspath));
  if (mkdir(saltspath, 0777) != 0 && errno != EEXIST) {
    fprintf(stderr, "failed to create .passc/salts directory at %s\n",
            saltspath);
  }

  strcpy(out, passcpath);
  return 0;
}

typedef struct PasscConfig {
  int loglevel;
  char datadir[PATH_MAX];
} PasscConfig;

PasscConfig *conf_get(void) {
  static PasscConfig conf;
  static int initialised = 0;

  if (!initialised) {
    conf.loglevel = 0;
    if (passc_dirinit(conf.datadir) < 0) {
      exit(EXIT_FAILURE);
    }

    initialised = 1;
  }

  return &conf;
}

void conf_set_loglevel(int lvl) {
  PasscConfig *conf = conf_get();
  conf->loglevel = lvl;
}

// verbose format logging if _passc_log_level is >= 1
void verbosef(const char *format, ...) {
  if (conf_get()->loglevel < 1)
    return;

  va_list args;

  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

// same as getline, but does not retain \n and exits on error. caller must
// free. returns chars written if ok, panics on err. retval can be 0.
size_t passc_getline(char **lineptr, size_t *linecap, FILE *stream) {
  ssize_t nread = getline(lineptr, linecap, stream);
  if (nread > 0) {
    (*lineptr)[--nread] = '\0';
  } else if (nread < 0) {
    fprintf(stderr, "panic: failed to read from stdin\n");
    free(*lineptr);
    exit(EXIT_FAILURE);
  }

  return nread;
}

// this does NOT retain \n. locks memory with sodium_mlock; callers
// responsibility to sodium_munlock and free. returns -1 on error, 0 on ok
ssize_t secure_getpassline(char **lineptr, size_t *linecap, FILE *stream) {
  struct termios old, new;

  if (tcgetattr(fileno(stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  // set our new flags
  if (tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
    return -1;

  ssize_t nread = passc_getline(lineptr, linecap, stream);
  printf("\n");

  if (sodium_mlock(*lineptr, *linecap) == 0) {
    verbosef("v: sodium_mlock ok\n");
  } else {
    verbosef("v: sodium_mlock failed; your platform may not support this. "
             "error: %s\n",
             strerror(errno));
  }

  // restore to old
  tcsetattr(fileno(stream), TCSAFLUSH, &old);
  return nread;
}

// generates a new salt, writing it to filepath. -1 on err, 0 if ok.
int write_new_salt(unsigned char *salt, size_t n, const char *filepath) {
  int retcode = 0;

  verbosef("v: making new random salt\n");
  randombytes_buf(salt, n);

  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    perror("gen_new_salt: couldn't open salt file for writing");
    return -1;
  }
  if (fwrite(salt, 1, n, fp) != n) {
    fprintf(stderr, "gen_new_salt: unexpected num of bytes written\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: new salt has been written at %s\n", filepath);

cleanup:
  fclose(fp);
  return retcode;
}

// tries to find a salt, or creates one with write_new_salt. 0 if ok, -1 on err.
int get_or_create_salt(unsigned char *salt, size_t n, const char *vname) {
  int retcode = 0;

  char filepath[PATH_MAX];
  const char *paths[4] = {conf_get()->datadir, "salts", vname, NULL};
  cwk_path_join_multiple(paths, filepath, sizeof(filepath));

  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    return write_new_salt(salt, n, filepath);
  }

  size_t readlen = fread(salt, 1, n, fp);
  if (ferror(fp) != 0) {
    perror("get_or_create_salt: failed to read salt file");
    retcode = -1;
    goto cleanup;
  } else if (readlen != n) {
    fprintf(
        stderr,
        "get_or_create_salt: read less bytes than required from salt file\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: using found salt file\n");

cleanup:
  fclose(fp);
  return retcode;
}

// quite an ugly function, should create some form of structured validation
// asks the user for an opslimit and memlimit; if unprovided or unparseable,
// defaults to MODERATE. returns -1 if out of bounds, 0 if ok.
int interactive_get_vaultoptions(unsigned int *opslimit, size_t *memlimit) {
  char *opsinp = NULL;
  size_t opscap = 0;

  printf("OPSLIMIT (moderate): ");
  passc_getline(&opsinp, &opscap, stdin);

  *opslimit = strtol(opsinp, NULL, 10);
  if (*opslimit == 0) {
    *opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
  } else if (*opslimit > crypto_pwhash_OPSLIMIT_MAX) {
    free(opsinp);
    fprintf(stderr, "opslimit was greater than the maximum permitted\n");
    return -1;
  }
  free(opsinp);

  char *meminp = NULL;
  size_t memcap = 0;

  printf("MEMLIMIT (moderate): ");
  passc_getline(&meminp, &memcap, stdin);

  *memlimit = strtol(meminp, NULL, 10);
  if (*memlimit == 0) {
    *memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
  } else if (*memlimit > crypto_pwhash_MEMLIMIT_MAX) {
    fprintf(stderr, "memlimit was greater than the maximum permitted\n");
    free(meminp);
    return -1;
  }

  free(meminp);
  return 0;
}

typedef struct VaultOptions {
  const char *name;
  unsigned int opslimit;
  size_t memlimit;
  int alg;
} VaultOptions;

// gets vault options from the user, inserts into db, and writes into vopts.
// returns -1 on err, 0 if ok.
int create_vaultoptions(sqlite3 *db, VaultOptions *vopts) {
  if (interactive_get_vaultoptions(&(vopts->opslimit), &(vopts->memlimit)) <
      0) {
    return -1;
  }
  vopts->alg = crypto_pwhash_ALG_DEFAULT; // use recommended alg

  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "INSERT INTO vaults (vname, opslimit, memlimit, "
      "alg) VALUES (%Q, %d, %d, %d)",
      vopts->name, vopts->opslimit, vopts->memlimit, vopts->alg);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "create_vaultoptions: failed to insert vaultoptions: %s\n",
            sqlite3_errmsg(db));

    sqlite3_finalize(stmt);
    sqlite3_free(queryt);
    return -1;
  }

  verbosef("v: inserted new vault options\n");
  return 0;
}

// gets vault options from db, otherwise calls create_vaultoptions. returns -1
// on err, 0 if ok. expects vopts->name to be set.
int get_or_create_vaultoptions(sqlite3 *db, VaultOptions *vopts) {
  sqlite3_stmt *stmt;
  char *queryt = sqlite3_mprintf(
      "SELECT opslimit, memlimit, alg FROM vaults WHERE vname = %Q",
      vopts->name);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "get_or_create_vaultoptions: failed to prepare query\n");
    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);
  queryt = NULL;

  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    // we already have the vault options
    vopts->opslimit = sqlite3_column_int(stmt, 0);
    vopts->memlimit = sqlite3_column_int(stmt, 1);
    vopts->alg = sqlite3_column_int(stmt, 2);

    sqlite3_finalize(stmt);
    verbosef("v: found vault hash options\n");
    return 0;
  }
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc == SQLITE_DONE) {
    // done, no rows; create new vault
    return create_vaultoptions(db, vopts);
  }

  // neither SQLITE_DONE nor SQLITE_ROW, fail
  fprintf(stderr,
          "get_or_create_vaultoptions: failed to select vault options from "
          "db: %s\n",
          sqlite3_errmsg(db));
  return -1;
}

// gets or creates a salt for vault then derives a key using vopts. -1 on err, 0
// if ok.
int pp_derivekey(unsigned char *out, size_t outlen, char *passphrase,
                 size_t pplen, VaultOptions *vopts) {
  unsigned char salt[crypto_pwhash_SALTBYTES];
  if (get_or_create_salt(salt, sizeof(salt), vopts->name) < 0) {
    return -1;
  }

  return crypto_pwhash(out, outlen, passphrase, pplen, salt, vopts->opslimit,
                       vopts->memlimit, vopts->alg);
}

// wrapper over crypto_pwhash_str, hashes a derived key.
int dk_keyhash(char *out, const unsigned char *const derivekey, size_t dklen) {
  return crypto_pwhash_str(out, (const char *const)derivekey, dklen,
                           crypto_pwhash_OPSLIMIT_INTERACTIVE,
                           crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

// wrapper over crypto_secretbox_easy, generating random nonce. expects nonce to
// be able to fit crypto_secretbox_NONCEBYTES
int pw_encrypt_secretbox(unsigned char *ciphertext, const unsigned char *pw,
                         unsigned long long pwlen, unsigned char *nonce,
                         unsigned char *key) {
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
  return crypto_secretbox_easy(ciphertext, pw, pwlen, nonce, key);
}

// reads a passphrase from stdin and derives its secret key using pp_derivekey.
// returns 0 if ok, -1 on err.
int interactive_derivekey(unsigned char *key, size_t keysize,
                          VaultOptions *vopts) {
  int retcode = 0;
  char *passphrase = NULL;
  size_t ppcap = 0;

  printf("Enter passphrase for vault: ");
  ssize_t readlen = secure_getpassline(&passphrase, &ppcap, stdin);
  if (readlen < 1) {
    if (readlen < 0) {
      fprintf(stderr,
              "interactive_derivekey: could not read passphrase from stdin\n");
    } else {
      fprintf(stderr, "passphrase is required\n");
    }

    retcode = -1;
    goto cleanup;
  }

  if (pp_derivekey(key, keysize, passphrase, readlen, vopts) != 0) {
    fprintf(stderr, "interactive_derivekey: failed to derive key\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: key has been derived\n");

cleanup:
  sodium_munlock(passphrase, ppcap);
  free(passphrase);
  return retcode;
}

// same as interactive_derivekey, except discards the key and returns the hash
// of the key instead. 0 if ok, -1 on error.
int interactive_derive_and_hash(char *outkeyhash, VaultOptions *vopts) {
  int retcode = 0;
  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  if (interactive_derivekey(key, sizeof(key), vopts) < 0) {
    retcode = -1;
    goto cleanup;
  }

  // we now have the key; hash this and store it so that, upon insertion into
  // the vault, we can check if it is the correct passphrase
  if (dk_keyhash(outkeyhash, key, sizeof(key)) != 0) {
    fprintf(stderr,
            "interactive_derive_and_hash: failed to hash derived key, OOM?\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: derived key has been hashed\n");

cleanup:
  sodium_munlock(key, sizeof(key));
  return retcode;
}

// migrates the database using MIGRATION_QUERY; returns 0 if ok, -1 on error.
// closes db on error.
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
  sqlite3 *db = NULL;
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

// creates a new vault. returns 0 if ok, -1 on error. this is the main function
// that should be used for creating new vaults. can also be used if the vault is
// half-made, i.e. the program was terminated after inserting the vault options
// but before adding the keyhash
int make_new_vault(sqlite3 *db, const char *vname) {
  int retcode = 0;
  char keyhash[crypto_pwhash_STRBYTES];

  printf("KEY CREATION: A key will be derived from your given passphrase.\n"
         "Ensure this is different to those used by other vaults.\n");

  VaultOptions vopts = {.name = vname};
  // create the vault options
  if (get_or_create_vaultoptions(db, &vopts) < 0) {
    return -1;
  }

  // read passphrase from user, derive secret key and hash secret key
  if (interactive_derive_and_hash(keyhash, &vopts) < 0) {
    return -1;
  }

  // update the vault row to include the keyhash
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "UPDATE vaults SET keyhash = %Q WHERE vname = %Q", keyhash, vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "make_new_vault: couldn't add keyhash to vault: %s\n",
            sqlite3_errmsg(db));

    retcode = -1;
    goto cleanup;
  }

  printf("Created new vault: %s\n", vname);

cleanup:
  sqlite3_free(queryt);
  sqlite3_finalize(stmt);
  return retcode;
}

// checks if a vault exists, creates if it doesn't. returns 1 if already exists,
// 0 on create, -1 on error.
int db_vault_init(sqlite3 *db, const char *vname) {
  // instead of 1, we select keyhash. this is in case the program was terminated
  // after the options were inserted, but before the keyhash was added.
  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("SELECT keyhash FROM vaults WHERE vname = %Q", vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "db_vault_init: could not prepare query: %s\n",
            sqlite3_errmsg(db));

    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);

  int retcode = 0;
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_DONE ||
      (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_NULL)) {
    printf("vault '%s' does not exist. creating...\n", vname);
    retcode = make_new_vault(db, vname);
  } else if (rc == SQLITE_ROW) {
    verbosef("v: vault found, continuing\n");
    retcode = 1;
  } else {
    fprintf(stderr, "db_vault_init: failed to advance query: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
  }

  sqlite3_finalize(stmt);
  return retcode;
}

// selects the keyhash from the db, used to verify passphrases. returns 0 if ok,
// -1 on error
int db_get_keyhash(char *out, sqlite3 *db, const char *vname) {
  int retcode = 0;

  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("SELECT keyhash FROM vaults WHERE vname = %Q", vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_ROW ||
      sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
    fprintf(stderr, "db_get_keyhash: failed to select keyhash: %s\n",
            sqlite3_errmsg(db));

    retcode = -1;
    goto cleanup;
  }

  strcpy(out, (const char *)sqlite3_column_text(stmt, 0));
  verbosef("v: found existing keyhash\n");

cleanup:
  sqlite3_free(queryt);
  sqlite3_finalize(stmt);
  return retcode;
}

typedef struct PasswordData {
  const unsigned char *ciphertext;
  size_t ctsize;
  const unsigned char *nonce;
  size_t ncesize;
  const char *ref;
  const char *vname;
} PasswordData;

// inserts a pw into db, returning the pw ID if ok, or -1 if not.
sqlite3_int64 db_insert_password(sqlite3 *db, PasswordData *pw) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf("INSERT INTO PASSWORDS (ref, vname, "
                                 "ciphertext, nonce) VALUES (%Q, %Q, ?, ?)",
                                 pw->ref, pw->vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "db_insert_password: failed to prepare query: %s\n",
            sqlite3_errmsg(db));
    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);

  sqlite3_bind_blob(stmt, 1, pw->ciphertext, pw->ctsize, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, pw->nonce, pw->ncesize, SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_insert_password: failed to insert pw: %s",
            sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  sqlite3_finalize(stmt);
  return sqlite3_last_insert_rowid(db);
}

// asks user for passphrase, derives key and verifies this against the db. key
// is written to key param. returns -1 on error, -2 if unauthorised, 0 if ok.
int vault_authorise(sqlite3 *db, unsigned char *key, size_t keysize,
                    const char *vname) {
  char dbhash[crypto_pwhash_STRBYTES];

  VaultOptions vopts = {.name = vname};
  if (get_or_create_vaultoptions(db, &vopts) < 0) {
    return -1;
  }

  if (interactive_derivekey(key, keysize, &vopts) < 0 ||
      db_get_keyhash(dbhash, db, vname) < 0) {
    return -1;
  }

  if (crypto_pwhash_str_verify(dbhash, (const char *const)key, keysize) != 0) {
    fprintf(stderr, "incorrect passphrase for '%s', unauthorised\n", vname);
    return -2;
  }

  printf("ok\n");
  return 0;
}

// calls vault_authorise, expecting a key of size crypto_secretbox_KEYBYTES.
int vault_authorise_discardkey(sqlite3 *dbhdl, const char *vname) {
  unsigned char key[crypto_secretbox_KEYBYTES];
  return vault_authorise(dbhdl, key, sizeof(key), vname);
}

// main function used for creating a db handle. runs db_init and
// db_vault_init. callers responsibility to sqlite3_close if 0 returned (ok)
int make_db(const char *vname, sqlite3 **outhdl) {
  char dbpath[PATH_MAX];
  cwk_path_join(conf_get()->datadir, "passc.db", dbpath, sizeof(dbpath));

  sqlite3 *db = NULL;
  if (db_init(dbpath, &db) < 0)
    return -1;

  if (db_vault_init(db, vname) < 0) {
    sqlite3_close(db);
    return -1;
  }

  *outhdl = db;
  return 0;
}

// steps a stmt, printing the rows in a human-readable format, returning the
// number of rows. returns -1 on error. assumes the first col is a rowid.
// last_rowid is set to the final rowid printed, or ignored if NULL.
int db_print_rows(sqlite3_stmt *stmt, sqlite3_int64 *last_rowid) {
  int rowcount = 0;

  int rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    rowcount++;
    const int nocols = sqlite3_column_count(stmt);

    sqlite3_int64 rowid = sqlite3_column_int64(stmt, 0);
    printf("%lld | ", rowid);
    if (last_rowid) {
      *last_rowid = rowid;
    }

    for (int i = 1; i < nocols; i++) {
      printf("%s ", sqlite3_column_text(stmt, i));

      if (i != nocols - 1) {
        printf("| ");
      }
    }
    printf("\n");

    rc = sqlite3_step(stmt);
  }

  if (rc != SQLITE_DONE) {
    return -1;
  }
  return rowcount;
}

// finds passwords matching the pattern %ref%, and asks the user to select one.
// if there is one match, it is returned immediately. returns -1 on error and
// pwid if ok. this is not guaranteed to be an existing pwid.
sqlite3_int64 interactive_pw_selection(sqlite3 *db, const char *ref,
                                       const char *vname) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "SELECT pwid, ref FROM passwords WHERE ref LIKE '%%%q%%' AND vname = %Q",
      ref, vname); // '%r%'

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "interactive_pw_selection: couldn't prepare stmt: %s\n",
            sqlite3_errmsg(db));

    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);
  queryt = NULL;

  sqlite3_int64 pwid = -1;
  int pwcount = db_print_rows(stmt, &pwid);
  if (pwcount <= 0) {
    if (pwcount < 0) {
      fprintf(stderr, "interactive_pw_selection: failed to list pws: %s\n",
              sqlite3_errmsg(db));
    } else {
      fprintf(stderr,
              "no passwords with that reference -- try using ls subcommand\n");
    }

    sqlite3_finalize(stmt);
    return -1;
  }

  sqlite3_finalize(stmt);
  stmt = NULL;

  if (pwcount != 1) {
    char *inp = NULL;
    size_t inpcap = 0;

    printf("Select password: ");
    if (passc_getline(&inp, &inpcap, stdin) < 1) {
      fprintf(stderr, "must select password\n");
      free(inp);
      return -1;
    }

    pwid = strtoll(inp, NULL, 10);
    free(inp);

    if (pwid == 0) {
      fprintf(stderr, "given PWID was either 0 or unable to be parsed\n");
      return -1;
    }
  }

  return pwid;
}

// prints refs and pwids to stdout; returns 0 if ok, -1 on error
int subcmd_list_passwords(sqlite3 *db, const char *vname) {
  int retcode = 0;

  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "SELECT pwid, ref FROM passwords WHERE vname = %Q", vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "subcmd_vault_list: couldn't prepare query: %s\n",
            sqlite3_errmsg(db));

    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);

  if (db_print_rows(stmt, NULL) < 0) {
    fprintf(stderr, "subcmd_list_passwords: failed to print rows: %s\n",
            sqlite3_errmsg(db));
    retcode = -1;
  }

  sqlite3_finalize(stmt);
  return retcode;
}

// subcommand to add a new password to a vault. returns 0 if ok, -1 on error.
int subcmd_add_password(sqlite3 *db, const char *ref, const char *vname) {
  int retcode = 0;

  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  if (vault_authorise(db, key, sizeof(key), vname) < 0) {
    sodium_munlock(key, sizeof(key));
    return -1;
  }

  char *pw = NULL;
  size_t pwcap = 0;

  printf("Password for '%s': ", ref);
  int pwlen = secure_getpassline(&pw, &pwcap, stdin);

  unsigned char ciphertext[crypto_secretbox_MACBYTES + pwlen];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  if (pwlen < 1) {
    fprintf(stderr, "password is required\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: encrypting password\n");
  if (pw_encrypt_secretbox(ciphertext, (const unsigned char *)pw, pwlen, nonce,
                           key) != 0) {
    fprintf(stderr, "subcmd_add_password: failed to encrypt pw\n");
    retcode = -1;
    goto cleanup;
  }

  sodium_munlock(key, sizeof(key));
  sodium_munlock(pw, pwcap);
  free(pw);
  verbosef("v: password has been encrypted\n");

  PasswordData pwdata = {
      .ciphertext = ciphertext,
      .ctsize = sizeof(ciphertext),
      .nonce = nonce,
      .ncesize = sizeof(nonce),
      .ref = ref,
      .vname = vname,
  };
  const sqlite3_int64 pwid = db_insert_password(db, &pwdata);

  if (pwid < 0) {
    return -1;
  }

  printf("Done. Password ID: %lld\n", pwid);
  return 0;

cleanup:
  sodium_munlock(pw, pwcap);
  free(pw);
  sodium_munlock(key, sizeof(key));
  return retcode;
}

int subcmd_rm_password(sqlite3 *db, const char *ref, const char *vname) {
  int retcode = 0;

  sqlite3_int64 pwid = interactive_pw_selection(db, ref, vname);
  if (pwid < 0) {
    return -1;
  }

  printf("Deleting password with PWID %lld. If you are unsure which password "
         "this is, use the 'get' subcommand to decrypt it before deletion.\n",
         pwid);

  if (vault_authorise_discardkey(db, vname) < 0) {
    return -1;
  }

  sqlite3_stmt *stmt;
  char *queryt =
      sqlite3_mprintf("DELETE FROM passwords WHERE pwid = %lld", pwid);
  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "subcmd_rm_password: failed to delete pw: %s\n",
            sqlite3_errmsg(db));

    retcode = -1;
    goto cleanup;
  }

  verbosef("v: pw has been deleted\n");

cleanup:
  sqlite3_free(queryt);
  sqlite3_finalize(stmt);
  return retcode;
}

// gets a password from the db and decrypts. -1 on err, 0 if ok.
int subcmd_get_password(sqlite3 *db, const char *ref, const char *vname) {
  sqlite3_int64 pwid = interactive_pw_selection(db, ref, vname);
  if (pwid < 0) {
    return -1;
  }

  sqlite3_stmt *stmt;
  char *queryt = sqlite3_mprintf("SELECT ciphertext, nonce FROM passwords "
                                 "WHERE pwid = %lld AND vname = %Q",
                                 pwid, vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "subcmd_get_password: failed to select cipher/nonce: %s\n",
            sqlite3_errmsg(db));

    free(queryt);
    return -1;
  }
  free(queryt);
  queryt = NULL;

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    fprintf(stderr, "could not get password\n");
    sqlite3_finalize(stmt);
    return -1;
  }

  const unsigned char *ciphertext = sqlite3_column_blob(stmt, 0);
  const int ctlen = sqlite3_column_bytes(stmt, 0);
  const unsigned char *nonce = sqlite3_column_blob(stmt, 1);

  unsigned char key[crypto_secretbox_KEYBYTES];
  if (vault_authorise(db, key, sizeof(key), vname) < 0) {
    sqlite3_finalize(stmt);
    return -1;
  }

  verbosef("v: decrypting password\n");
  unsigned char pw[ctlen - crypto_secretbox_MACBYTES + 1];
  sodium_mlock(pw, sizeof(pw));

  if (crypto_secretbox_open_easy(pw, ciphertext, ctlen, nonce, key) != 0) {
    fprintf(stderr, "FAILED to verify & decrypt. This should not be possible; "
                    "the passphrase matched. It is most likely that the salt "
                    "or ciphertext has been corrupted.\n");

    sodium_munlock(pw, sizeof(pw));
    sqlite3_finalize(stmt);
    return -1;
  }

  pw[sizeof(pw) - 1] = '\0';
  printf("\nPWID: %lld\n--------\n%s\n", pwid, pw);

  sodium_munlock(pw, sizeof(pw));
  sqlite3_finalize(stmt);
  return 0;
}

// prints usage to stderr
void perr_usage(const char *pname) {
  fprintf(stderr,
          "Usage:\n"
          "  %s [-v vault_name] (add|rm|get) <reference, e.g. example.org>\n"
          "  %s [-v vault_name] ls\n"
          "\n"
          "Options:\n"
          "  -V Enable verbose logging.\n",
          pname, pname); // could use %n$, but this is a compiler warning
}

typedef int (*SubcmdHandler)(sqlite3 *db, const char *arg,
                             const char *vault_name);
typedef int (*SubcmdHandlerNoArg)(sqlite3 *db, const char *vault_name);

typedef struct PasscSubcmd {
  const char *name;
  SubcmdHandler handler;
  SubcmdHandlerNoArg handler_noarg;
} PasscSubcmd;

int main(int argc, char **argv) {
  const char *pname = argv[0];
  if (sodium_init() < 0) {
    fprintf(stderr, "%s: sodium_init failed\n", pname);
    return EXIT_FAILURE;
  }

  const char *vault_name = NULL;

  // OPTION MATCHING
  int opt;
  while ((opt = getopt(argc, argv, "Vv::")) != -1) {
    switch (opt) {
    case 'v':
      vault_name = optarg;
      break;
    case 'V':
      conf_set_loglevel(1);
      break;
    default: // '?'
      perr_usage(pname);
      return EXIT_FAILURE;
    }
  }

  if (!vault_name)
    vault_name = "main";

  if (optind >= argc) {
    fprintf(stderr, "%s: expected subcommand\n", pname);
    perr_usage(pname);
    return EXIT_FAILURE;
  }

  sqlite3 *db = NULL;
  if (make_db(vault_name, &db) < 0) {
    fprintf(stderr, "couldn't initialise database\n");
    return EXIT_FAILURE;
  }

  PasscSubcmd subcmds[] = {
      {"ls", NULL, subcmd_list_passwords},
      {"add", subcmd_add_password, NULL},
      {"rm", subcmd_rm_password, NULL},
      {"get", subcmd_get_password, NULL},
  };
  const int no_subcmds = sizeof(subcmds) / sizeof(subcmds[0]);

  int retcode = EXIT_SUCCESS;
  char *subcmd = argv[optind];
  int found = 0;

  for (int i = 0; i < no_subcmds; i++) {
    if (strcmp(subcmd, subcmds[i].name) == 0) {
      found = 1;
      if (subcmds[i].handler_noarg) {
        retcode = subcmds[i].handler_noarg(db, vault_name);
      } else {
        if (optind + 1 >= argc) {
          fprintf(stderr, "%s: expected argument\n", pname);
          perr_usage(pname);

          retcode = EXIT_FAILURE;
          break;
        }
        retcode = subcmds[i].handler(db, argv[optind + 1], vault_name);
      }

      if (retcode < 0) {
        fprintf(stderr, "command '%s' failed for vault '%s'\n", subcmds[i].name,
                vault_name);
      }

      break;
    }
  }

  if (!found) {
    fprintf(stderr, "%s: unknown subcommand\n", pname);
    retcode = EXIT_FAILURE;
  }

  sqlite3_close(db);
  return retcode;
}
