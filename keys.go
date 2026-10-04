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

// CreateAPIKey makes a new key with the given scopes, stores its hash,
// and returns the key itself. This is the only moment the plaintext key
// exists on the server. The key and its scopes are created in one transaction.
func (s *Store) CreateAPIKey(name string, scopes []Scope) (string, error) {
	key, err := generateAPIKey()
	if err != nil {
		return "", err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO api_keys (name, key_hash) VALUES (?, ?)`,
		name, hashAPIKey(key),
	)
	if err != nil {
		return "", err
	}

	keyID, err := res.LastInsertId()
	if err != nil {
		return "", err
	}

	for _, sc := range scopes {
		_, err := tx.Exec(
			`INSERT OR IGNORE INTO key_scopes (key_id, action, pattern) VALUES (?, ?, ?)`,
			keyID, sc.Action, sc.Pattern,
		)
		if err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return key, nil
}

// GrantScopes adds scopes to an existing, non-revoked key (looked up by name).
func (s *Store) GrantScopes(keyName string, scopes []Scope) error {
	var keyID int64
	err := s.db.QueryRow(
		`SELECT id FROM api_keys WHERE name = ? AND revoked_at IS NULL`,
		keyName,
	).Scan(&keyID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	for _, sc := range scopes {
		_, err := s.db.Exec(
			`INSERT OR IGNORE INTO key_scopes (key_id, action, pattern) VALUES (?, ?, ?)`,
			keyID, sc.Action, sc.Pattern,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadScopes returns every scope granted to a key.
func (s *Store) LoadScopes(keyID int64) ([]Scope, error) {
	rows, err := s.db.Query(
		`SELECT action, pattern FROM key_scopes WHERE key_id = ?`,
		keyID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scope
	for rows.Next() {
		var sc Scope
		if err := rows.Scan(&sc.Action, &sc.Pattern); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
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