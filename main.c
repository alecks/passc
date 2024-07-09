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
ssize_t secure_getline(char **lineptr, size_t *linecap, FILE *stream) {
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
int salt_create(unsigned char *salt, size_t n, const char *filepath) {
  verbosef("v: making new random salt\n");
  randombytes_buf(salt, n);

  FILE *fp = fopen(filepath, "w");
  if (!fp) {
    perror("salt_create: couldn't open salt file for writing");
    return -1;
  }

  size_t written = fwrite(salt, 1, n, fp);
  fclose(fp);
  if (written != n) {
    fprintf(stderr, "salt_create: unexpected num of bytes written\n");
    return -1;
  }

  verbosef("v: new salt has been written at %s\n", filepath);
  return 0;
}

// tries to find a salt, or creates one with write_new_salt. 0 if ok, -1 on err.
int salt_get_or_create(unsigned char *salt, size_t n, const char *vname) {
  int retcode = 0;

  char filepath[PATH_MAX];
  const char *paths[4] = {conf_get()->datadir, "salts", vname, NULL};
  cwk_path_join_multiple(paths, filepath, sizeof(filepath));

  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    return salt_create(salt, n, filepath);
  }

  size_t readlen = fread(salt, 1, n, fp);
  int ferr = ferror(fp);
  fclose(fp);
  fp = NULL;

  if (ferr != 0) {
    perror("salt_get_or_create: failed to read salt file");
    return -1;
  } else if (readlen != n) {
    fprintf(
        stderr,
        "salt_get_or_create: read less bytes than required from salt file\n");
    return -1;
  }

  verbosef("v: using found salt file\n");
  return retcode;
}

typedef struct VaultParameters {
  const char *name;
  unsigned int opslimit;
  size_t memlimit;
  int alg;
} VaultParameters;

// quite an ugly function, should create some form of structured validation
// asks the user for an opslimit and memlimit; if unprovided or unparseable,
// defaults to MODERATE. returns -1 if out of bounds, 0 if ok.
int interactive_get_vaultparams(VaultParameters *vopts) {
  char *opsinp = NULL;
  size_t opscap = 0;

  printf("OPSLIMIT (moderate): ");
  passc_getline(&opsinp, &opscap, stdin);

  vopts->opslimit = strtol(opsinp, NULL, 10);
  if (vopts->opslimit == 0) {
    vopts->opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
  } else if (vopts->opslimit < crypto_pwhash_OPSLIMIT_MIN ||
             vopts->opslimit > crypto_pwhash_OPSLIMIT_MAX) {
    free(opsinp);
    fprintf(stderr, "opslimit was outwith permitted values\n");
    return -1;
  }
  free(opsinp);

  char *meminp = NULL;
  size_t memcap = 0;

  printf("MEMLIMIT (moderate): ");
  passc_getline(&meminp, &memcap, stdin);

  vopts->memlimit = strtol(meminp, NULL, 10);
  if (vopts->memlimit == 0) {
    vopts->memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
  } else if (vopts->memlimit < crypto_pwhash_MEMLIMIT_MIN ||
             vopts->memlimit > crypto_pwhash_MEMLIMIT_MAX) {
    fprintf(stderr, "memlimit was outwith permitted values\n");
    free(meminp);
    return -1;
  }

  vopts->alg = crypto_pwhash_ALG_DEFAULT; // use recommended

  free(meminp);
  return 0;
}

// gets vault options from the user, inserts into db, and writes into vopts. if
// overwrite is 1, UPDATE is used. returns -1 on err, 0 if ok.
int vaultparams_create(sqlite3 *db, VaultParameters *vopts, int overwrite) {
  if (interactive_get_vaultparams(vopts) < 0) {
    return -1;
  }

  sqlite3_stmt *stmt = NULL;
  char *queryt = NULL;
  if (overwrite) {
    queryt = sqlite3_mprintf("UPDATE vaults SET opslimit = %d, memlimit = %d, "
                             "alg = %d WHERE vname = %Q",
                             vopts->opslimit, vopts->memlimit, vopts->alg,
                             vopts->name);
  } else {
    queryt = sqlite3_mprintf("INSERT INTO vaults (vname, opslimit, memlimit, "
                             "alg) VALUES (%Q, %d, %d, %d)",
                             vopts->name, vopts->opslimit, vopts->memlimit,
                             vopts->alg);
  }

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "vaultparams_create: failed to prepare stmt: %s",
            sqlite3_errmsg(db));
    return -1;
  }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "vaultparams_create: sqlite didnt return DONE: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  verbosef("v: inserted new vault parameters\n");
  return 0;
}

// gets vault options from db, otherwise calls vaultparams_create. returns -1
// on err, 0 if ok. expects vopts->name to be set.
int vaultparams_get_or_create(sqlite3 *db, VaultParameters *vopts) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "SELECT opslimit, memlimit, alg FROM vaults WHERE vname = %Q",
      vopts->name);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "vaultopts_get_or_create: failed to prepare query\n");
    return -1;
  }

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    // we already have the vault options
    vopts->opslimit = sqlite3_column_int(stmt, 0);
    vopts->memlimit = sqlite3_column_int(stmt, 1);
    vopts->alg = sqlite3_column_int(stmt, 2);

    verbosef("v: found vault hash options\n");
    sqlite3_finalize(stmt);
    return 0;
  }
  sqlite3_finalize(stmt);

  if (rc == SQLITE_DONE) {
    // done, no rows; create new vault
    return vaultparams_create(db, vopts, 0);
  }

  // neither SQLITE_DONE nor SQLITE_ROW, fail
  fprintf(stderr,
          "vaultopts_get_or_create: failed to select vault options from "
          "db: %s\n",
          sqlite3_errmsg(db));
  return -1;
}

// gets or creates a salt for vault then derives a key using vopts. -1 on err, 0
// if ok.
int pp_derivekey(unsigned char *out, size_t outlen, char *passphrase,
                 size_t pplen, VaultParameters *vopts) {
  unsigned char salt[crypto_pwhash_SALTBYTES];
  if (salt_get_or_create(salt, sizeof(salt), vopts->name) < 0) {
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
                         const unsigned char *key) {
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
  return crypto_secretbox_easy(ciphertext, pw, pwlen, nonce, key);
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
int db_open(const char *filename, sqlite3 **outhdl) {
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

// selects the keyhash from the db, used to verify passphrases. returns 0 if ok,
// -1 on error
int db_vault_get_keyhash(char *out, sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("SELECT keyhash FROM vaults WHERE vname = %Q", vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_vault_get_keyhash: failed to prepare query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  if (sqlite3_step(stmt) != SQLITE_ROW ||
      sqlite3_column_type(stmt, 0) != SQLITE_TEXT) {
    fprintf(stderr, "db_get_keyhash: failed to select keyhash: %s\n",
            sqlite3_errmsg(db));

    sqlite3_finalize(stmt);
    return -1;
  }

  strcpy(out, (const char *)sqlite3_column_text(stmt, 0));
  verbosef("v: found existing keyhash\n");
  sqlite3_finalize(stmt);
  return 0;
}

typedef struct PasswordData {
  const unsigned char *ciphertext;
  const size_t ctsize;
  const unsigned char *nonce;

  const sqlite3_int64 pwid;
  const char *ref;
  const char *vname;
} PasswordData;

// inserts a pw into db, returning the pw ID if ok, or -1 if not.
sqlite3_int64 db_password_insert(sqlite3 *db, PasswordData *pw) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf("INSERT INTO PASSWORDS (ref, vname, "
                                 "ciphertext, nonce) VALUES (%Q, %Q, ?, ?)",
                                 pw->ref, pw->vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_insert_password: failed to prepare query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_bind_blob(stmt, 1, pw->ciphertext, pw->ctsize, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, pw->nonce, crypto_secretbox_NONCEBYTES,
                    SQLITE_STATIC);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "db_insert_password: failed to insert pw: %s",
            sqlite3_errmsg(db));
    return -1;
  }

  return sqlite3_last_insert_rowid(db);
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

// reads a passphrase from stdin and derives its secret key using pp_derivekey.
// returns 0 if ok, -1 on err.
int interactive_derivekey_key(unsigned char *key, size_t keysize,
                              VaultParameters *vopts) {
  char *passphrase = NULL;
  size_t ppcap = 0;

  printf("\nEnter passphrase for vault: ");
  ssize_t readlen = secure_getline(&passphrase, &ppcap, stdin);
  if (readlen < 1) {
    if (readlen < 0) {
      fprintf(stderr,
              "interactive_derivekey: could not read passphrase from stdin\n");
    } else {
      fprintf(stderr, "passphrase is required\n");
    }

    sodium_munlock(passphrase, ppcap);
    free(passphrase);
    return -1;
  }

  int rc = pp_derivekey(key, keysize, passphrase, readlen, vopts);
  sodium_munlock(passphrase, ppcap);
  free(passphrase);

  if (rc != 0) {
    fprintf(stderr, "interactive_derivekey: failed to derive key\n");
    return -1;
  }

  verbosef("v: key has been derived\n");
  return 0;
}

int interactive_derivekey_key_hash(unsigned char *outkey, size_t outkeysize,
                                   char *outkeyhash, VaultParameters *vopts) {
  if (interactive_derivekey_key(outkey, outkeysize, vopts) < 0) {
    return -1;
  }

  if (dk_keyhash(outkeyhash, outkey, outkeysize) != 0) {
    fprintf(stderr,
            "interactive_derivekey_hash: failed to hash derived key, OOM?\n");
    return -1;
  }

  verbosef("v: derived key has been hashed\n");
  return 0;
}

// same as interactive_derivekey, except discards the key and returns the hash.
// 0 if ok, -1 on error.
int interactive_derivekey_hash(char *outkeyhash, VaultParameters *vopts) {
  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  int rc = interactive_derivekey_key_hash(key, sizeof(key), outkeyhash, vopts);

  sodium_munlock(key, sizeof(key));
  return rc;
}

// asks user for passphrase, derives key and verifies this against the db. key
// is written to key param. returns -1 on error, -2 if unauthorised, 0 if ok.
int interactive_vault_auth(sqlite3 *db, unsigned char *key, size_t keysize,
                           const char *vname) {
  char dbhash[crypto_pwhash_STRBYTES];

  VaultParameters vopts = {.name = vname};
  if (vaultparams_get_or_create(db, &vopts) < 0 ||
      interactive_derivekey_key(key, keysize, &vopts) < 0 ||
      db_vault_get_keyhash(dbhash, db, vname) < 0) {
    return -1;
  }

  if (crypto_pwhash_str_verify(dbhash, (const char *const)key, keysize) != 0) {
    fprintf(stderr, "incorrect passphrase for '%s', unauthorised\n", vname);
    return -2;
  }

  printf("OK\n\n");
  return 0;
}

// calls vault_authorise, expecting a key of size crypto_secretbox_KEYBYTES.
int interactive_vault_auth_discard(sqlite3 *dbhdl, const char *vname) {
  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  int rc = interactive_vault_auth(dbhdl, key, sizeof(key), vname);

  sodium_munlock(key, sizeof(key));
  return rc;
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

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "interactive_pw_selection: couldn't prepare stmt: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_int64 pwid = -1;
  int pwcount = db_print_rows(stmt, &pwid);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (pwcount <= 0) {
    if (pwcount < 0) {
      fprintf(stderr, "interactive_pw_selection: failed to list pws: %s\n",
              sqlite3_errmsg(db));
    } else {
      fprintf(stderr,
              "no passwords with that reference -- try using ls subcommand\n");
    }

    return -1;
  }

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

int db_vault_set_keyhash(sqlite3 *db, const char *vname, const char *keyhash) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "UPDATE vaults SET keyhash = %Q WHERE vname = %Q", keyhash, vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_vault_set_keyhash: failed to prepare query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "db_vault_set_keyhash: couldn't add keyhash to vault: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

// creates a new vault. returns 0 if ok, -1 on error. this is the main function
// that should be used for creating new vaults. can also be used if the vault is
// half-made, i.e. the program was terminated after inserting the vault options
// but before adding the keyhash
int vault_create(sqlite3 *db, const char *vname) {
  printf("\nKEY CREATION: A key will be derived from your given passphrase.\n"
         "Ensure this is different to those used by other vaults.\n");

  VaultParameters vopts = {.name = vname};
  // create the vault options, or get we already have them
  if (vaultparams_get_or_create(db, &vopts) < 0) {
    return -1;
  }

  // read passphrase from user, derive secret key and hash secret key, set in db
  char keyhash[crypto_pwhash_STRBYTES];
  if (interactive_derivekey_hash(keyhash, &vopts) < 0 ||
      db_vault_set_keyhash(db, vname, keyhash) < 0) {
    return -1;
  }

  printf("Created new vault: %s\n", vname);
  return 0;
}

// checks if a vault exists, creates if it doesn't. returns 1 if already exists,
// 0 on create, -1 on error.
int vault_init(sqlite3 *db, const char *vname) {
  // instead of 1, we select keyhash. this is in case the program was terminated
  // after the options were inserted, but before the keyhash was added.
  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("SELECT keyhash FROM vaults WHERE vname = %Q", vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "vault_init: could not prepare query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  rc = sqlite3_step(stmt);
  int coltype = sqlite3_column_type(stmt, 0);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc == SQLITE_DONE || (rc == SQLITE_ROW && coltype == SQLITE_NULL)) {
    printf("vault '%s' does not exist. creating...\n", vname);
    return vault_create(db, vname);
  } else if (rc == SQLITE_ROW) {
    verbosef("v: vault found, continuing\n");
    return 1;
  } else {
    fprintf(stderr, "vault_init: failed to advance query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }
}

// main function used for creating a db handle. runs db_init and
// vault_init. callers responsibility to sqlite3_close if 0 returned (ok)
int vault_db_init(const char *vname, sqlite3 **outhdl) {
  char dbpath[PATH_MAX];
  cwk_path_join(conf_get()->datadir, "passc.db", dbpath, sizeof(dbpath));

  sqlite3 *db = NULL;
  if (db_open(dbpath, &db) < 0)
    return -1;

  if (vault_init(db, vname) < 0) {
    sqlite3_close(db);
    return -1;
  }

  *outhdl = db;
  return 0;
}

// prints refs and pwids to stdout; returns 0 if ok, -1 on error
int subcmd_list_vault_passwords(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "SELECT pwid, ref FROM passwords WHERE vname = %Q", vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "subcmd_list_vault_passwords: couldn't prepare query: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  rc = db_print_rows(stmt, NULL);
  sqlite3_finalize(stmt);
  stmt = NULL;
  if (rc < 0) {
    fprintf(stderr, "subcmd_list_vault_passwords: failed to print rows: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

// updates a password, for rotating its key. requires pw->pwid, ciphertext,
// ctsize, nonce. returns -1 on err, 0 if ok.
int db_password_update(sqlite3 *db, PasswordData *pw) {
  sqlite3_stmt *stmt;
  char *queryt = sqlite3_mprintf(
      "UPDATE passwords SET ciphertext = ?, nonce = ? WHERE pwid = ?");

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_password_update: failed to prepare stmt: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_bind_blob(stmt, 1, pw->ciphertext, pw->ctsize, SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, pw->nonce, crypto_secretbox_NONCEBYTES,
                    SQLITE_STATIC);
  sqlite3_bind_int64(stmt, 3, pw->pwid);

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "db_password_update: failed to update password: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

// uses o_key to decrypt a pw, encrypts it with n_key and a new nonce, and
// writes to the db. returns -1 on err, 0 if ok.
int rotate_password(sqlite3 *db, PasswordData *o_pw, const unsigned char *o_key,
                    const unsigned char *n_key) {
  const int ptlen = o_pw->ctsize - crypto_secretbox_MACBYTES;
  unsigned char *plaintext = malloc(ptlen);
  sodium_mlock(plaintext, ptlen);

  if (crypto_secretbox_open_easy(plaintext, o_pw->ciphertext, o_pw->ctsize,
                                 o_pw->nonce, o_key) != 0) {
    fprintf(stderr, "rotate_password: failed to open secretbox\n");

    sodium_munlock(plaintext, ptlen);
    free(plaintext);
    return -1;
  }

  unsigned char n_nonce[crypto_secretbox_NONCEBYTES];
  unsigned char *n_ct = malloc(o_pw->ctsize);

  int rc = pw_encrypt_secretbox(n_ct, plaintext, ptlen, n_nonce, n_key);

  sodium_munlock(plaintext, ptlen);
  free(plaintext);
  plaintext = NULL;

  if (rc != 0) {
    free(n_ct);
    fprintf(stderr, "rotate_password: failed to encrypt secretbox\n");
    return -1;
  }

  PasswordData pw = {.pwid = o_pw->pwid,
                     .ciphertext = n_ct,
                     .ctsize = o_pw->ctsize,
                     .nonce = n_nonce};
  rc = db_password_update(db, &pw);
  free(n_ct);
  if (rc < 0) {
    return -1;
  }

  verbosef("v: updated password %lld\n", pw.pwid);
  return 0;
}

// runs rotate_password on every pw in vname. returns -1 on err, 0 if ok.
int rotate_vault_passwords(sqlite3 *db, const char *vname,
                           const unsigned char *o_key,
                           const unsigned char *n_key) {
  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "SELECT pwid, ciphertext, nonce FROM passwords WHERE vname = %Q", vname);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "rotate_vault_passwords: failed to prepare query\n");
    return -1;
  }

  rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    PasswordData o_pw = {
        .pwid = sqlite3_column_int64(stmt, 0),
        .ciphertext = sqlite3_column_blob(stmt, 1),
        .ctsize = sqlite3_column_bytes(stmt, 1),
        .nonce = sqlite3_column_blob(stmt, 2),
    };
    if (rotate_password(db, &o_pw, o_key, n_key) < 0) {
      sqlite3_finalize(stmt);
      return -1;
    }

    rc = sqlite3_step(stmt);
  }
  sqlite3_finalize(stmt);

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "rotate_vault_passwords: sqlite didnt return DONE: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  return 0;
}

// changes a vault's key. -1 on err, 0 if ok.
int subcmd_rotate_vault(sqlite3 *db, const char *vname) {
  printf("\nKEY ROTATION: You will be prompted for new vault parameters, then "
         "you will be prompted for the current passphrase of vault '%s'. You "
         "can then specify a new passphrase for the vault, which will use the "
         "parameters specified initially.\n\n",
         vname);

  VaultParameters n_vopts = {.name = vname};
  if (interactive_get_vaultparams(&n_vopts) < 0) {
    return -1;
  }

  unsigned char o_key[crypto_secretbox_KEYBYTES];
  sodium_mlock(o_key, sizeof(o_key));
  printf("Current: ");
  if (interactive_vault_auth(db, o_key, sizeof(o_key), vname) < 0) {
    sodium_munlock(o_key, sizeof(o_key));
    return -1;
  }

  unsigned char n_key[crypto_secretbox_KEYBYTES];
  sodium_mlock(n_key, sizeof(n_key));
  char n_keyhash[crypto_pwhash_STRBYTES];

  printf("New: ");
  if (interactive_derivekey_key_hash(n_key, sizeof(n_key), n_keyhash,
                                     &n_vopts) < 0) {
    sodium_munlock(o_key, sizeof(o_key));
    sodium_munlock(n_key, sizeof(n_key));
    return -1;
  }

  int rc = rotate_vault_passwords(db, vname, o_key, n_key);
  sodium_munlock(o_key, sizeof(o_key));
  sodium_munlock(n_key, sizeof(n_key));
  if (rc < 0) {
    return -1;
  }

  printf("Vault key has been rotated. New keyhash: %s\n", n_keyhash);
  return db_vault_set_keyhash(db, vname, n_keyhash);
}

// TODO: tidy
// subcommand to add a new password to a vault. returns 0 if ok, -1 on error.
int subcmd_add_password(sqlite3 *db, const char *ref, const char *vname) {
  int retcode = 0;

  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  if (interactive_vault_auth(db, key, sizeof(key), vname) < 0) {
    sodium_munlock(key, sizeof(key));
    return -1;
  }

  char *pw = NULL;
  size_t pwcap = 0;

  printf("Password for '%s': ", ref);
  int pwlen = secure_getline(&pw, &pwcap, stdin);

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
      .ref = ref,
      .vname = vname,
  };
  const sqlite3_int64 pwid = db_password_insert(db, &pwdata);

  if (pwid < 0) {
    return -1;
  }

  printf("\nDone. Password ID: %lld\n", pwid);
  return 0;

cleanup:
  sodium_munlock(pw, pwcap);
  free(pw);
  sodium_munlock(key, sizeof(key));
  return retcode;
}

int subcmd_rm_password(sqlite3 *db, const char *ref, const char *vname) {
  sqlite3_int64 pwid = interactive_pw_selection(db, ref, vname);
  if (pwid < 0) {
    return -1;
  }

  printf("Deleting password with PWID %lld. If you are unsure which password "
         "this is, use the 'get' subcommand to decrypt it before deletion.\n",
         pwid);
  if (interactive_vault_auth_discard(db, vname) < 0) {
    return -1;
  }

  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("DELETE FROM passwords WHERE pwid = %lld", pwid);

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "subcmd_rm_password: failed to prepare statement: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  stmt = NULL;

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "subcmd_rm_password: failed to delete pw: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  verbosef("v: pw has been deleted\n");
  return 0;
}

// TODO: tidy
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

  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);
  queryt = NULL;

  if (rc != SQLITE_OK) {
    fprintf(stderr, "subcmd_get_password: failed to prepare stmt: %s\n",
            sqlite3_errmsg(db));
    return -1;
  }

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    fprintf(stderr, "could not get password\n");
    sqlite3_finalize(stmt);
    return -1;
  }

  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));
  if (interactive_vault_auth(db, key, sizeof(key), vname) < 0) {
    sodium_munlock(key, sizeof(key));
    sqlite3_finalize(stmt);
    return -1;
  }

  const unsigned char *ciphertext = sqlite3_column_blob(stmt, 0);
  const unsigned char *nonce = sqlite3_column_blob(stmt, 1);

  const int ctlen = sqlite3_column_bytes(stmt, 0);
  const size_t pw_s = ctlen - crypto_secretbox_MACBYTES + 1;

  unsigned char *pw = malloc(pw_s);
  sodium_mlock(pw, pw_s);

  verbosef("v: decrypting password\n");
  rc = crypto_secretbox_open_easy(pw, ciphertext, ctlen, nonce, key);

  sodium_munlock(key, sizeof(key));
  sqlite3_finalize(stmt);

  if (rc != 0) {
    fprintf(stderr, "FAILED to verify & decrypt. This should not be possible; "
                    "the passphrase matched. It is most likely that the salt "
                    "or ciphertext has been corrupted.\n");

    sodium_munlock(pw, pw_s);
    free(pw);
    return -1;
  }

  pw[pw_s - 1] = '\0';
  printf("\nPWID: %lld\n--------\n%s\n", pwid, pw);

  sodium_munlock(pw, pw_s);
  free(pw);
  return 0;
}

// prints usage to stderr
void perr_usage(void) {
  // clang-format off
  fprintf(stderr,
          "Usage:\n"
          "  passc [-vVaultName] (add|rm|get) <reference>  Add, remove or get a password.\n"
          "  passc [-vVaultName] ls                        List passwords in a vault.\n"
          "  passc [-vVaultName] rotate                    Changes the passphrase for a vault.\n"
          "\n"
          "Options:\n"
          "  -V Enable verbose logging.\n");
  // clang-format on
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
      perr_usage();
      return EXIT_FAILURE;
    }
  }

  if (!vault_name)
    vault_name = "main";

  if (optind >= argc) {
    fprintf(stderr, "%s: expected subcommand\n", pname);
    perr_usage();
    return EXIT_FAILURE;
  }

  sqlite3 *db = NULL;
  if (vault_db_init(vault_name, &db) < 0) {
    fprintf(stderr, "couldn't initialise database\n");
    return EXIT_FAILURE;
  }

  PasscSubcmd subcmds[] = {
      {"add", subcmd_add_password, NULL},
      {"rm", subcmd_rm_password, NULL},
      {"get", subcmd_get_password, NULL},
      {"ls", NULL, subcmd_list_vault_passwords},
      {"rotate", NULL, subcmd_rotate_vault},
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
          perr_usage();

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
