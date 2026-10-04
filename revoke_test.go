package main

import (
	"errors"
	"os"
	"testing"
)

func TestRevokeKey(t *testing.T) {
	const path = "revoke_test_tmp.db"
	cleanup := func() {
		os.Remove(path)
		os.Remove(path + "-wal")
		os.Remove(path + "-shm")
	}
	cleanup()
	t.Cleanup(cleanup)

	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db)

	key, err := store.CreateAPIKey("temp-key", []Scope{{Action: "read", Pattern: "*"}})
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.ValidateAPIKey(key); err != nil {
		t.Fatalf("new key should be valid: %v", err)
	}

	if err := store.RevokeKey("temp-key"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.ValidateAPIKey(key); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("revoked key should be invalid, got %v", err)
	}

	if err := store.RevokeKey("temp-key"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking twice should return ErrNotFound, got %v", err)
	}
	if err := store.RevokeKey("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown key should return ErrNotFound, got %v", err)
	}
}