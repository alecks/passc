#include "cwalk.h"
#include <errno.h>
#include <pwd.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define MIGRATION_QUERY                                                        \
  "CREATE TABLE IF NOT EXISTS vaults"                                          \
  "(vname TEXT PRIMARY KEY);"                                                  \
  "CREATE TABLE IF NOT EXISTS passwords ("                                     \
  "pname TEXT PRIMARY KEY,"                                                    \
  "ciphertext BLOB NOT NULL,"                                                  \
  "vname INTEGER NOT NULL,"                                                    \
  "FOREIGN KEY (vname) REFERENCES vaults (vname));"

void perr_usage(char *pname) {
  fprintf(stderr,
          "Usage:\n"
          "  %1$s [-n vault_name] (add|rm|get) <password name>\n"
          "  %1$s [-n vault_name] ls\n"
          "\n"
          "Options:\n"
          "  -v Enable verbose logging.\n",
          pname);
}

int _passc_log_level = 0;

void verbosef(const char *format, ...) {
  if (_passc_log_level < 1)
    return;

  va_list args;

  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

// from gnu getpass manual: reads a password from stream until \n. this
// implementation does NOT retain \n at end of string.
ssize_t passc_getpassline(char **lineptr, size_t *n, FILE *stream) {
  struct termios old, new;
  int nread;

  if (tcgetattr(fileno(stream), &old) != 0)
    return -1;
  new = old;
  new.c_lflag &= ~ECHO;
  // set terminal to new
  if (tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
    return -1;

  nread = getline(lineptr, n, stream);
  (*lineptr)[--nread] = '\0'; // replace \n

  // restores terminal to old
  tcsetattr(fileno(stream), TCSAFLUSH, &old);
  printf("\n");
  return nread;
}

void get_homedir(char *outdir) {
  char *dir;
  struct passwd *pwd = getpwuid(getuid());
  if (pwd) {
    dir = pwd->pw_dir;
  } else {
    dir = getenv("HOME");
  }

  if (!dir) {
    dir = ".";
  }
  strcpy(outdir, dir);
}

int gen_new_salt(unsigned char *salt, size_t n, char *filepath) {
  verbosef("v: making new random salt\n");
  randombytes_buf(salt, n);

  FILE *fp = fopen(filepath, "w");
  if (fp == NULL) {
    fprintf(stderr, "couldn't open salt file for writing\n");
    return -1;
  }
  if (fwrite(salt, 1, n, fp) != n) {
    fclose(fp);
    fprintf(stderr, "bytes of salt written didn't match expected\n");
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
  if (fp == NULL) {
    return gen_new_salt(salt, n, filepath);
  }

  size_t len = fread(salt, 1, n, fp);
  if (len != n || ferror(fp) != 0) {
    fprintf(stderr, "failed to read salt file\n");
    fclose(fp);
    return -1;
  }

  fclose(fp);
  verbosef("using found salt file\n");
  return 1;
}

// creates a new derived key from user passphrase
int gen_vault_derived_key() {
  char *passphrase = NULL;
  size_t plen = 0;

  printf("A key will be derived from your given passphrase.\n"
         "Ensure this is different to those used by other vaults.\n"
         "Enter passphrase: ");

  ssize_t nread = passc_getpassline(&passphrase, &plen, stdin);
  if (nread == -1) {
    free(passphrase);
    fprintf(stderr, "could not read passphrase from stdin\n");
    return -1;
  }

  unsigned char salt[crypto_pwhash_SALTBYTES];
  unsigned char key[crypto_secretbox_KEYBYTES];

  if (find_salt(salt, sizeof(salt)) < 0) {
    free(passphrase);
    return -1;
  }
  verbosef("v: deriving key from passphrase\n");
  if (crypto_pwhash(key, sizeof(key), passphrase, nread, salt,
                    crypto_pwhash_OPSLIMIT_MODERATE,
                    crypto_pwhash_MEMLIMIT_MODERATE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    free(passphrase);
    fprintf(stderr, "out of memory, couldn't derive key from pw\n");
    return -1;
  }
  free(passphrase);
  passphrase = NULL;

  // TODO: keys

  return 0;
}

int db_migrate_up(sqlite3 *db) {
  char *errmsg = NULL;
  sqlite3_exec(db, MIGRATION_QUERY, NULL, NULL, &errmsg);

  if (errmsg) {
    fprintf(stderr, "failed to migrate db: %s\n", errmsg);
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
    fprintf(stderr, "failed to open sqlite3 db: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  *outhdl = db;
  verbosef("v: sqlite3 db opened\n");
  return db_migrate_up(db);
}

// creates a new vault. returns 0 if successful, otherwise negative.
int db_vault_create(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;

  verbosef("v: starting key creation process\n");
  if (gen_vault_derived_key() < 0)
    return -1;

  char *queryt =
      sqlite3_mprintf("INSERT INTO vaults (vname) VALUES (%Q)", vname);
  int rc = sqlite3_prepare(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "could not prepare query: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  int res = 0;
  if (sqlite3_step(stmt) == SQLITE_DONE) {
    printf("created new vault: %s\n", vname);
  } else {
    fprintf(stderr, "failed to advance query: %s\n", sqlite3_errmsg(db));
    res = -1;
  }

  sqlite3_finalize(stmt);
  return res;
}

// checks if a vault exists, creates if it doesn't. returns 1 if already exists,
// 0 on create, negative if error.
int db_vault_init(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;

  char *queryt =
      sqlite3_mprintf("SELECT 1 FROM vaults WHERE vname = %Q", vname);
  int rc = sqlite3_prepare_v2(db, queryt, -1, &stmt, NULL);
  sqlite3_free(queryt);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "could not prepare query: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  int res = -1;
  rc = sqlite3_step(stmt);
  switch (rc) {
  case SQLITE_DONE:
    res = db_vault_create(db, vname);
    break;
  case SQLITE_ROW:
    verbosef("v: vault found, continuing\n");
    res = 1;
    break;
  default:
    fprintf(stderr, "failed to advance query: %d %s\n", rc, sqlite3_errmsg(db));
    res = -1;
  }

  sqlite3_finalize(stmt);
  return res;
}

// main function used for creating a db handle. runs db_init and
// db_vault_init. callers responsibility to sqlite3_close.
int make_db(const char *vname, sqlite3 **outhdl) {
  sqlite3 *db;
  if (db_init("passc.db", &db) < 0)
    return -1;

  *outhdl = db;
  return db_vault_init(db, vname);
}

int subcmd_vault_list(const char *vname) {
  sqlite3 *db;
  if (make_db(vname, &db) < 0)
    return -1;

  printf("unimplemented\n");
  return 0;
}

int passc_dirinit() {
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

  int opt;
  const char *vault_name = "main";

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

  // this is after getopt; contains verbose logging
  if (passc_dirinit() != 0)
    return EXIT_FAILURE;

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
  } else {
    fprintf(stderr, "%s: unknown subcommand '%s'\n", pname, subcmd);
    perr_usage(pname);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
