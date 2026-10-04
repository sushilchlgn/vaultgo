package main

import (
	"os"
	"testing"
)

func TestOutcomeFor(t *testing.T) {
	cases := map[int]string{
		200: "ok",
		201: "ok",
		401: "unauthenticated",
		403: "denied",
		404: "not_found",
		400: "rejected",
		409: "rejected",
		500: "error",
	}
	for status, want := range cases {
		if got := outcomeFor(status); got != want {
			t.Errorf("outcomeFor(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	const path = "audit_test_tmp.db"
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
	if err := store.WriteAudit(0, "tester", "read", "db-password", 1, 200, "ok", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	entries, err := store.RecentAudit(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d (err %v)", len(entries), err)
	}

	if _, err := db.Exec(`UPDATE audit_log SET outcome = 'tampered'`); err == nil {
		t.Error("UPDATE on audit_log should be rejected")
	}
	if _, err := db.Exec(`DELETE FROM audit_log`); err == nil {
		t.Error("DELETE on audit_log should be rejected")
	}
}