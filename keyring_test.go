package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// hexKey returns a valid 64-character hex key made of one repeated byte.
func hexKey(b byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", b), 32)
}

func TestParseKeyring(t *testing.T) {
	kr, err := parseKeyring("1:" + hexKey(1) + ",2:" + hexKey(2))
	if err != nil {
		t.Fatal(err)
	}
	if kr.CurrentID() != 2 {
		t.Errorf("current id = %d, want 2 (the highest)", kr.CurrentID())
	}
	if kr.Size() != 2 {
		t.Errorf("size = %d, want 2", kr.Size())
	}
}

func TestParseKeyringRejectsBadInput(t *testing.T) {
	good := hexKey(1)
	bad := []string{
		"",
		"nocolon",
		"x:" + good,
		"0:" + good,
		"1:zz",
		"1:abcd",
		"1:" + good + ",1:" + good,
	}
	for _, spec := range bad {
		if _, err := parseKeyring(spec); err == nil {
			t.Errorf("parseKeyring(%q) should fail", spec)
		}
	}
}

func TestKeyringEncryptsWithCurrentKey(t *testing.T) {
	kr, err := parseKeyring("1:" + hexKey(1) + ",2:" + hexKey(2))
	if err != nil {
		t.Fatal(err)
	}

	ct, nonce, id, err := kr.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if id != 2 {
		t.Fatalf("encrypted under key %d, want 2", id)
	}

	got, err := kr.Decrypt(id, ct, nonce)
	if err != nil || !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("round trip failed: %q, %v", got, err)
	}

	if _, err := kr.Decrypt(1, ct, nonce); err == nil {
		t.Error("decrypting with the wrong key must fail")
	}
	if _, err := kr.Decrypt(9, ct, nonce); err == nil {
		t.Error("decrypting with an unknown key id must fail")
	}
}

func TestOldDataStaysReadableAfterAddingANewKey(t *testing.T) {
	oldRing, err := parseKeyring("1:" + hexKey(1))
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce, id, err := oldRing.Encrypt([]byte("written before rotation"))
	if err != nil {
		t.Fatal(err)
	}

	newRing, err := parseKeyring("2:" + hexKey(2) + ",1:" + hexKey(1))
	if err != nil {
		t.Fatal(err)
	}

	got, err := newRing.Decrypt(id, ct, nonce)
	if err != nil || string(got) != "written before rotation" {
		t.Fatalf("old data should still decrypt: %q, %v", got, err)
	}
}