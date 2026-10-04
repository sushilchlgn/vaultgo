package main

import (
	"os"
	"testing"
)

// openTempStore opens a throwaway database next to the tests.
func openTempStore(t *testing.T, path string) *Store {
	t.Helper()

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
	t.Cleanup(func() { db.Close() })

	return NewStore(db)
}

func TestRewrapMovesVersionsToCurrentKey(t *testing.T) {
	store := openTempStore(t, "rewrap_test_tmp.db")

	oldRing, err := parseKeyring("1:" + hexKey(1))
	if err != nil {
		t.Fatal(err)
	}

	ct, n, id, _ := oldRing.Encrypt([]byte("first-value"))
	if _, err := store.CreateSecret("s", ct, n, id); err != nil {
		t.Fatal(err)
	}
	ct, n, id, _ = oldRing.Encrypt([]byte("second-value"))
	if _, err := store.AddVersion("s", ct, n, id); err != nil {
		t.Fatal(err)
	}

	counts, err := store.CountByKey()
	if err != nil || counts[1] != 2 {
		t.Fatalf("before rewrap: counts = %v, err = %v", counts, err)
	}

	newRing, err := parseKeyring("2:" + hexKey(2) + ",1:" + hexKey(1))
	if err != nil {
		t.Fatal(err)
	}

	total, err := Rewrap(store, newRing)
	if err != nil || total != 2 {
		t.Fatalf("Rewrap = %d, %v; want 2, nil", total, err)
	}

	counts, _ = store.CountByKey()
	if counts[1] != 0 || counts[2] != 2 {
		t.Fatalf("after rewrap: counts = %v, want everything on key 2", counts)
	}

	// The plaintext history must be unchanged.
	for v, want := range map[int]string{1: "first-value", 2: "second-value"} {
		sv, err := store.GetVersion("s", v)
		if err != nil {
			t.Fatal(err)
		}
		if sv.KeyID != 2 {
			t.Errorf("version %d is on key %d, want 2", v, sv.KeyID)
		}
		got, err := newRing.Decrypt(sv.KeyID, sv.Ciphertext, sv.Nonce)
		if err != nil || string(got) != want {
			t.Errorf("version %d decrypts to %q, %v; want %q", v, got, err, want)
		}
	}

	// A second run has nothing left to do.
	if total, err := Rewrap(store, newRing); err != nil || total != 0 {
		t.Errorf("second Rewrap = %d, %v; want 0, nil", total, err)
	}
}

func TestRewrapFailsSafelyWhenOldKeyIsMissing(t *testing.T) {
	store := openTempStore(t, "rewrap_missing_tmp.db")

	oldRing, err := parseKeyring("1:" + hexKey(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, n, id, _ := oldRing.Encrypt([]byte("value"))
	if _, err := store.CreateSecret("s", ct, n, id); err != nil {
		t.Fatal(err)
	}

	// Key 1 was removed from the ring too early.
	ringWithoutOld, err := parseKeyring("2:" + hexKey(2))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Rewrap(store, ringWithoutOld); err == nil {
		t.Fatal("rewrap must fail when an older key is missing")
	}

	counts, _ := store.CountByKey()
	if counts[1] != 1 {
		t.Errorf("a failed rewrap must leave data untouched, counts = %v", counts)
	}
}