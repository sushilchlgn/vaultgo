package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newTestCrypter(t *testing.T) *Crypter {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := NewCrypter(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestCrypter(t)
	plain := []byte("super-secret-db-password")

	ct, nonce, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := c.Decrypt(ct, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	c := newTestCrypter(t)

	ct, nonce, err := c.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	ct[0] ^= 0xFF // flip some bits

	if _, err := c.Decrypt(ct, nonce); err == nil {
		t.Fatal("expected decryption to fail on tampered data")
	}
}

func TestNonceIsUniquePerEncryption(t *testing.T) {
	c := newTestCrypter(t)

	_, n1, _ := c.Encrypt([]byte("same"))
	_, n2, _ := c.Encrypt([]byte("same"))

	if bytes.Equal(n1, n2) {
		t.Fatal("nonces must differ between encryptions")
	}
}