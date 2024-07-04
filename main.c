#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
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
          "  %1$s [-n vault_name] info\n"
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

// db init opens the db and migrates up. callers responsibility to run
// sqlite3_close, unless return value is <0. if outhdl is NULL it's ignored.
int db_init(const char *filename, sqlite3 **outhdl) {
  sqlite3 *db;
  int rc = sqlite3_open_v2(filename, &db,
                           SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "failed to open sqlite3 db: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return -1;
  }

  if (outhdl) {
    *outhdl = db;
  }
  verbosef("v: sqlite3 db opened\n");
  return db_migrate_up(db);
}

// creates a new vault. returns 0 if successful, otherwise negative.
int vault_create(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;

  const char *querytext =
      sqlite3_mprintf("INSERT INTO vaults (vname) VALUES (%Q)", vname);
  int rc = sqlite3_prepare(db, querytext, -1, &stmt, NULL);
  sqlite3_free(querytext);

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
int vault_init(sqlite3 *db, const char *vname) {
  sqlite3_stmt *stmt;

  const char *query =
      sqlite3_mprintf("SELECT 1 FROM vaults WHERE vname = %Q", vname);
  int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
  sqlite3_free(query);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "could not prepare query: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return -1;
  }

  int res = -1;
  rc = sqlite3_step(stmt);
  switch (rc) {
  case SQLITE_DONE:
    res = vault_create(db, vname);
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

int main(int argc, char **argv) {
  if (sodium_init() < 0) {
    fprintf(stderr, "%s: sodium_init failed\n", argv[0]);
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
      perr_usage(argv[0]);
      return EXIT_FAILURE;
    }
  }

  if (optind >= argc) {
    fprintf(stderr, "%s: expected subcommand\n", argv[0]);
    perr_usage(argv[0]);
    return EXIT_FAILURE;
  }

  sqlite3 *db;
  if (db_init("passc.db", &db) < 0) {
    fprintf(stderr, "failed to initialise database\n");
    return EXIT_FAILURE;
  }

  verbosef("v: using vault %s\n", vault_name);
  if (vault_init(db, vault_name) < 0) {
    fprintf(stderr, "failed to initialise vault\n");
    return EXIT_FAILURE;
  }

  sqlite3_close(db);
  return EXIT_SUCCESS;
}
