package main

import (
	"database/sql"
	"os"
	"testing"
)

const oldSchema = `
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE secret_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL REFERENCES secrets(id),
    version INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (secret_id, version)
);
INSERT INTO secrets (name) VALUES ('old-secret');
INSERT INTO secret_versions (secret_id, version, ciphertext, nonce) VALUES (1, 1, x'00', x'00');
`

func TestOpenDBMigratesOldDatabase(t *testing.T) {
	const path = "migrate_test_tmp.db"
	cleanup := func() {
		os.Remove(path)
		os.Remove(path + "-wal")
		os.Remove(path + "-shm")
	}
	cleanup()
	t.Cleanup(cleanup)

	// Build a database the way the code did before key rotation existed.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(oldSchema); err != nil {
		old.Close()
		t.Fatal(err)
	}
	old.Close()

	// Opening it with the current code must add key_id, defaulting to 1.
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}

	var keyID int
	if err := db.QueryRow(`SELECT key_id FROM secret_versions`).Scan(&keyID); err != nil {
		t.Fatalf("key_id should exist after migration: %v", err)
	}
	if keyID != 1 {
		t.Errorf("existing rows should get key id 1, got %d", keyID)
	}
	db.Close()

	// Opening it again must be a harmless no-op.
	db, err = openDB(path)
	if err != nil {
		t.Fatalf("second open should succeed: %v", err)
	}
	db.Close()
}