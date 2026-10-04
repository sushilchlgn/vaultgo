package main

import (
	"database/sql"
	_ "embed"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// openDB opens (or creates) the SQLite file, makes sure the tables exist,
// and upgrades older databases.
func openDB(path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// migrate upgrades databases created before key rotation existed.
// CREATE TABLE IF NOT EXISTS does not add columns to an existing table,
// so the key_id column is added here when it is missing. Existing rows
// get key id 1, which matches a single VAULT_MASTER_KEY.
func migrate(db *sql.DB) error {
	var n int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('secret_versions') WHERE name = 'key_id'`,
	).Scan(&n)
	if err != nil {
		return err
	}

	if n == 0 {
		_, err = db.Exec(`ALTER TABLE secret_versions ADD COLUMN key_id INTEGER NOT NULL DEFAULT 1`)
		return err
	}
	return nil
}