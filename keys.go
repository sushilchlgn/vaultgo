package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

const keyPrefix = "vgo_"

var ErrInvalidKey = errors.New("invalid api key")

// generateAPIKey returns a key with 256 bits of randomness.
func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return keyPrefix + hex.EncodeToString(b), nil
}

// hashAPIKey returns the SHA-256 hash of a key, hex encoded.
// Only this hash is ever stored.
func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey makes a new key, stores its hash, and returns the key itself.
// This is the only moment the plaintext key exists on the server.
func (s *Store) CreateAPIKey(name string) (string, error) {
	key, err := generateAPIKey()
	if err != nil {
		return "", err
	}

	_, err = s.db.Exec(
		`INSERT INTO api_keys (name, key_hash) VALUES (?, ?)`,
		name, hashAPIKey(key),
	)
	if err != nil {
		return "", err
	}

	return key, nil
}

// ValidateAPIKey checks a presented key and returns the caller's id and name.
// Revoked keys are rejected.
func (s *Store) ValidateAPIKey(key string) (int64, string, error) {
	var id int64
	var name string

	err := s.db.QueryRow(
		`SELECT id, name FROM api_keys
		 WHERE key_hash = ? AND revoked_at IS NULL`,
		hashAPIKey(key),
	).Scan(&id, &name)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrInvalidKey
	}
	if err != nil {
		return 0, "", err
	}

	return id, name, nil
}