package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Crypter encrypts and decrypts secret values with AES-256-GCM.
type Crypter struct {
	aead cipher.AEAD
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

// Keyring holds every master key the server knows. New data is encrypted
// with the key that has the highest id; any key in the ring can decrypt.
// That is what lets old and new keys coexist during a rotation.
type Keyring struct {
	crypters map[int]*Crypter
	current  int
}

// CurrentID is the id of the key used for all new encryption.
func (k *Keyring) CurrentID() int { return k.current }

// Size is how many keys are loaded.
func (k *Keyring) Size() int { return len(k.crypters) }

// Encrypt seals plaintext with the current key and says which key was used.
func (k *Keyring) Encrypt(plaintext []byte) (ciphertext, nonce []byte, keyID int, err error) {
	ciphertext, nonce, err = k.crypters[k.current].Encrypt(plaintext)
	if err != nil {
		return nil, nil, 0, err
	}
	return ciphertext, nonce, k.current, nil
}

// Decrypt opens data with the key it was encrypted under.
func (k *Keyring) Decrypt(keyID int, ciphertext, nonce []byte) ([]byte, error) {
	c, ok := k.crypters[keyID]
	if !ok {
		return nil, fmt.Errorf("no key with id %d in the keyring", keyID)
	}
	return c.Decrypt(ciphertext, nonce)
}

// parseKeyring reads a spec like "2:<64 hex chars>,1:<64 hex chars>".
// Error messages never include key material.
func parseKeyring(spec string) (*Keyring, error) {
	kr := &Keyring{crypters: make(map[int]*Crypter)}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idStr, hexKey, ok := strings.Cut(part, ":")
		if !ok {
			return nil, errors.New("each key must look like id:hexkey")
		}

		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil || id < 1 {
			return nil, fmt.Errorf("key id %q must be a positive integer", idStr)
		}
		if _, dup := kr.crypters[id]; dup {
			return nil, fmt.Errorf("duplicate key id %d", id)
		}

		key, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			return nil, fmt.Errorf("key %d is not valid hex", id)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key %d must be 32 bytes (64 hex characters), got %d bytes", id, len(key))
		}

		c, err := NewCrypter(key)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", id, err)
		}

		kr.crypters[id] = c
		if id > kr.current {
			kr.current = id
		}
	}

	if len(kr.crypters) == 0 {
		return nil, errors.New("no keys found")
	}
	return kr, nil
}

// loadKeyring reads the keys from the environment.
//
//	VAULT_MASTER_KEYS  "2:<hex>,1:<hex>"  several keys, highest id is current
//	VAULT_MASTER_KEY   "<hex>"            one key, treated as id 1
func loadKeyring() (*Keyring, error) {
	multi := os.Getenv("VAULT_MASTER_KEYS")
	single := os.Getenv("VAULT_MASTER_KEY")

	switch {
	case multi != "" && single != "":
		return nil, errors.New("set only one of VAULT_MASTER_KEYS and VAULT_MASTER_KEY")
	case multi != "":
		return parseKeyring(multi)
	case single != "":
		return parseKeyring("1:" + single)
	default:
		return nil, errors.New("VAULT_MASTER_KEY (or VAULT_MASTER_KEYS) is not set")
	}
}

// generateKeyHex returns a fresh random 256-bit key as 64 hex characters.
func generateKeyHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}