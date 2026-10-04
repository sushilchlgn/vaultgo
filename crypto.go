package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// Crypter encrypts and decrypts secret values with AES-256-GCM.
type Crypter struct {
	aead cipher.AEAD
}

// loadMasterKey reads the hex-encoded 32-byte key from the environment.
func loadMasterKey() ([]byte, error) {
	h := os.Getenv("VAULT_MASTER_KEY")
	if h == "" {
		return nil, errors.New("VAULT_MASTER_KEY is not set")
	}

	key, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("VAULT_MASTER_KEY must be hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("VAULT_MASTER_KEY must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}

	return key, nil
}

// NewCrypter builds an AES-256-GCM cipher from a 32-byte key.
func NewCrypter(key []byte) (*Crypter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Crypter{aead: aead}, nil
}

// Encrypt seals the plaintext with a fresh random nonce.
// Store both the ciphertext and the nonce; you need both to decrypt.
func (c *Crypter) Encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, c.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = c.aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt opens the ciphertext. It fails if the data or nonce was
// tampered with, or if the wrong key is used.
func (c *Crypter) Decrypt(ciphertext, nonce []byte) ([]byte, error) {
	return c.aead.Open(nil, nonce, ciphertext, nil)
}