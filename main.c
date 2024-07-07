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
  "pwid INTEGER PRIMARY KEY,"                                                  \
  "ref TEXT NOT NULL,"                                                         \
  "ciphertext BLOB NOT NULL,"                                                  \
  "nonce BLOB NOT NULL,"                                                       \
  "vname INTEGER NOT NULL,"                                                    \
  "FOREIGN KEY (vname) REFERENCES vaults (vname));"                            \
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

// runs mkdir for the homedir/.passc directory. uses get_homedir; cwd will be
// used instead if unavailable. -1 on error, 0 if ok
int passc_dirinit(char *out) {
  char pth[PATH_MAX];
  char homedir[PATH_MAX];

  get_homedir(homedir);
  cwk_path_join(homedir, ".passc", pth, sizeof(pth));

  errno = 0;
  if (mkdir(pth, 0777) != 0 && errno != EEXIST) {
    fprintf(stderr, "failed to create .passc directory at %s\n", pth);
    return -1;
  }

  strcpy(out, pth);
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

  ssize_t nread = getline(lineptr, linecap, stream);
  if (nread > 0) {
    (*lineptr)[--nread] = '\0'; // replace \n
  }
  printf("\n");

  if (sodium_mlock(*lineptr, *linecap) != 0) {
    verbosef("v: sodium_mlock failed; your platform may not support this. "
             "error: %s\n",
             strerror(errno));
  }

  // restore to old
  tcsetattr(fileno(stream), TCSAFLUSH, &old);
  return nread;
}

// same as getline, but does not retain \n
ssize_t passc_getline(char **lineptr, size_t *linecap, FILE *stream) {
  ssize_t nread = getline(lineptr, linecap, stream);
  if (nread > 0) {
    (*lineptr)[--nread] = '\0';
  }
  return nread;
}

int gen_new_salt(unsigned char *salt, size_t n, const char *filepath) {
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

int find_salt(unsigned char *salt, size_t n) {
  int retcode = 0;

  char filepath[PATH_MAX];
  cwk_path_join(conf_get()->datadir, "salt", filepath, sizeof(filepath));

  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    return gen_new_salt(salt, n, filepath);
  }

  size_t readlen = fread(salt, 1, n, fp);
  if (ferror(fp) != 0) {
    perror("find_salt: failed to read salt file");
    retcode = -1;
    goto cleanup;
  } else if (readlen != n) {
    fprintf(stderr,
            "find_salt: read less bytes than required from salt file\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: using found salt file\n");

cleanup:
  fclose(fp);
  return retcode;
}

// wrapper over crypto_pwhash using the salt file. derives key from passphrase.
int pp_derivekey(unsigned char *out, size_t outlen, char *passphrase,
                 size_t pplen) {
  unsigned char salt[crypto_pwhash_SALTBYTES];
  if (find_salt(salt, sizeof(salt)) < 0) {
    return -1;
  }

  return crypto_pwhash(
      out, outlen, passphrase, pplen, salt, crypto_pwhash_OPSLIMIT_MODERATE,
      crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT);
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

// reads a passphrase from stdin and derives a key from it; 0 if ok, -1 on error
int getpassline_derivekey(unsigned char *key, size_t keysize) {
  int retcode = 0;
  char *passphrase = NULL;
  size_t ppcap = 0;

  printf("Enter passphrase for vault: ");
  ssize_t readlen = secure_getpassline(&passphrase, &ppcap, stdin);
  if (readlen < 1) {
    if (readlen < 0) {
      fprintf(stderr,
              "getpassline_derivekey: could not read passphrase from stdin\n");
    } else {
      fprintf(stderr, "passphrase is required\n");
    }

    retcode = -1;
    goto cleanup;
  }

  if (pp_derivekey(key, keysize, passphrase, readlen) != 0) {
    fprintf(stderr, "getpassline_derivekey: failed to derive key, OOM?\n");
    retcode = -1;
    goto cleanup;
  }

  verbosef("v: key has been derived\n");

cleanup:
  sodium_munlock(passphrase, ppcap);
  free(passphrase);
  return retcode;
}

// same as derivekey_getpassline, except discards the key and returns the hash
// of the key instead. 0 if ok, -1 on error.
int getpassline_keyhash(char *outkeyhash) {
  int retcode = 0;
  unsigned char key[crypto_secretbox_KEYBYTES];
  sodium_mlock(key, sizeof(key));

  if (getpassline_derivekey(key, sizeof(key)) < 0) {
    retcode = -1;
    goto cleanup;
  }

  // we now have the key; hash this and store it so that, upon insertion into
  // the vault, we can check if it is the correct passphrase
  if (dk_keyhash(outkeyhash, key, sizeof(key)) != 0) {
    fprintf(stderr, "keyhash_getpassline: failed to hash derived key, OOM?\n");
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

// creates a new vault. returns 0 if ok, -1 on error.
int db_vault_create(sqlite3 *db, const char *vname) {
  int retcode = 0;
  char keyhash[crypto_pwhash_STRBYTES];

  printf("KEY CREATION: A key will be derived from your given passphrase.\n"
         "Ensure this is different to those used by other vaults.\n");
  if (getpassline_keyhash(keyhash) < 0)
    return -1;

  sqlite3_stmt *stmt = NULL;
  char *queryt = sqlite3_mprintf(
      "INSERT INTO vaults (vname, keyhash) VALUES (%Q, %Q)", vname, keyhash);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK ||
      sqlite3_step(stmt) != SQLITE_DONE) {
    fprintf(stderr, "db_vault_create: couldn't insert vault: %s\n",
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
  sqlite3_stmt *stmt = NULL;
  char *queryt =
      sqlite3_mprintf("SELECT 1 FROM vaults WHERE vname = %Q", vname);

  if (sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL) != SQLITE_OK) {
    fprintf(stderr, "db_vault_init: could not prepare query: %s\n",
            sqlite3_errmsg(db));

    sqlite3_free(queryt);
    return -1;
  }
  sqlite3_free(queryt);

  int retcode;
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
      sqlite3_step(stmt) != SQLITE_ROW) {
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
int db_insert_password(sqlite3 *db, PasswordData *pw) {
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
int vault_authorise(sqlite3 *dbhdl, unsigned char *key, size_t keysize,
                    const char *vname) {
  char dbhash[crypto_pwhash_STRBYTES];

  if (getpassline_derivekey(key, keysize) < 0 ||
      db_get_keyhash(dbhash, dbhdl, vname) < 0) {
    return -1;
  }

  if (crypto_pwhash_str_verify(dbhash, (const char *const)key, keysize) != 0) {
    fprintf(stderr, "incorrect passphrase for '%s', unauthorised\n", vname);
    return -2;
  }

  printf("ok\n");
  return 0;
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
// number of rows. returns -1 on error.
int db_print_rows(sqlite3_stmt *stmt) {
  int rowcount = 0;

  int rc = sqlite3_step(stmt);
  while (rc == SQLITE_ROW) {
    rowcount++;
    const int nocols = sqlite3_column_count(stmt);

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
    return -1;
  }
  return rowcount;
}

// finds passwords matching the pattern %ref%, and asks the user to select one
// using the pwid. if there is only one match, 0 is returned. returns -1 on err,
// 0 if pwid not provided by user or one match, and pwid if ok.
long interactive_pw_selection(sqlite3 *db, const char *ref, const char *vname) {
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

  int pwcount = db_print_rows(stmt);
  if (pwcount < 1) {
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

  long pwid = 0;
  if (pwcount != 1) {
    char *inp = NULL;
    size_t inpcap = 0;

    printf("Select password: ");
    if (passc_getline(&inp, &inpcap, stdin) < 0) {
      fprintf(stderr, "interactive_pw_selection: couldn't read from stdin\n");
      return -1;
    }
    pwid = strtol(inp, NULL, 10);
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

  if (db_print_rows(stmt) < 0) {
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

  if (pw_encrypt_secretbox(ciphertext, (const unsigned char *)pw, pwlen, nonce,
                           key) != 0) {
    fprintf(stderr, "subcmd_add_password: failed to encrypt pw\n");
    retcode = -1;
    goto cleanup;
  }

  sodium_munlock(key, sizeof(key));
  sodium_munlock(pw, pwcap);
  free(pw);

  PasswordData pwdata = {
      .ciphertext = ciphertext,
      .ctsize = sizeof(ciphertext),
      .nonce = nonce,
      .ncesize = sizeof(nonce),
      .ref = ref,
      .vname = vname,
  };
  const int pwid = db_insert_password(db, &pwdata);

  if (pwid < 0) {
    return -1;
  }

  printf("Done. Password ID: %d\n", pwid);
  return 0;

cleanup:
  sodium_munlock(pw, pwcap);
  free(pw);
  sodium_munlock(key, sizeof(key));
  return retcode;
}

int subcmd_rm_password(sqlite3 *db, const char *ref, const char *vname) {
  long pwid = interactive_pw_selection(db, ref, vname);
  if (pwid < 0) {
    return -1;
  }

  printf("unimplemented\n");

  return 0;
}

// gets a password from the db and decrypts. -1 on err, 0 if ok.
int subcmd_get_password(sqlite3 *db, const char *ref, const char *vname) {
  long pwid = interactive_pw_selection(db, ref, vname);
  if (pwid < 0) {
    return -1;
  }

  sqlite3_stmt *stmt;
  char *queryt =
      sqlite3_mprintf("SELECT pwid, ciphertext, nonce FROM passwords "
                      "WHERE (pwid = %d OR ref = %Q) AND vname = %Q",
                      pwid, ref, vname);

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

  pwid = sqlite3_column_int(stmt, 0);
  const unsigned char *ciphertext = sqlite3_column_blob(stmt, 1);
  const int ctlen = sqlite3_column_bytes(stmt, 1);
  const unsigned char *nonce = sqlite3_column_blob(stmt, 2);

  unsigned char key[crypto_secretbox_KEYBYTES];
  if (vault_authorise(db, key, sizeof(key), vname) < 0) {
    sqlite3_finalize(stmt);
    return -1;
  }

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
  printf("\nPWID: %ld\n--------\n%s\n", pwid, pw);

  sodium_munlock(pw, sizeof(pw));
  sqlite3_finalize(stmt);
  return 0;
}

typedef int (*SubcmdHandler)(sqlite3 *db, const char *arg,
                             const char *vault_name);
typedef int (*SubcmdHandlerNoArg)(sqlite3 *db, const char *vault_name);

typedef struct PasscSubcmd {
  const char *name;
  SubcmdHandler handler;
  SubcmdHandlerNoArg handler_noarg;
} PasscSubcmd;

// prints usage to stderr
void perr_usage(const char *pname) {
  fprintf(stderr,
          "Usage:\n"
          "  %s [-n vault_name] (add|rm|get) <reference, e.g. example.org>\n"
          "  %s [-n vault_name] ls\n"
          "\n"
          "Options:\n"
          "  -v Enable verbose logging.\n",
          pname, pname); // could use %n$, but this is a compiler warning
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
        fprintf(stderr, "failed to execute '%s' for vault '%s'\n",
                subcmds[i].name, vault_name);
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
