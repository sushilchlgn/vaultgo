package main

import (
	"database/sql"
	"errors"
	"strings"
)

var (
	ErrSecretExists = errors.New("secret already exists")
	ErrNotFound     = errors.New("secret or version not found")
)

type SecretVersion struct {
	Version    int
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  string
}

// VersionInfo is the metadata of a version, with no secret material.
type VersionInfo struct {
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// CreateSecret inserts a new secret and its first version in one transaction,
// so you never end up with a secret that has no version.
func (s *Store) CreateSecret(name string, ciphertext, nonce []byte) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() // does nothing after a successful Commit

	res, err := tx.Exec(`INSERT INTO secrets (name) VALUES (?)`, name)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrSecretExists
		}
		return 0, err
	}

	secretID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	_, err = tx.Exec(
		`INSERT INTO secret_versions (secret_id, version, ciphertext, nonce)
		 VALUES (?, 1, ?, ?)`,
		secretID, ciphertext, nonce,
	)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return 1, nil
}

// AddVersion appends a new version to an existing secret and returns its number.
// The next version number is computed inside the INSERT itself, so the
// read-and-write is one atomic statement. The UNIQUE (secret_id, version)
// constraint is the backstop if two writers ever collide.
func (s *Store) AddVersion(name string, ciphertext, nonce []byte) (int, error) {
	var version int
	err := s.db.QueryRow(
		`INSERT INTO secret_versions (secret_id, version, ciphertext, nonce)
		 SELECT s.id,
		        COALESCE((SELECT MAX(version) FROM secret_versions WHERE secret_id = s.id), 0) + 1,
		        ?, ?
		 FROM secrets s
		 WHERE s.name = ?
		 RETURNING version`,
		ciphertext, nonce, name,
	).Scan(&version)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return version, nil
}

// ListVersions returns version numbers and timestamps, newest first.
func (s *Store) ListVersions(name string) ([]VersionInfo, error) {
	rows, err := s.db.Query(
		`SELECT v.version, v.created_at
		 FROM secrets s
		 JOIN secret_versions v ON v.secret_id = s.id
		 WHERE s.name = ?
		 ORDER BY v.version DESC`,
		name,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VersionInfo
	for rows.Next() {
		var vi VersionInfo
		if err := rows.Scan(&vi.Version, &vi.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, vi)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Every secret has at least one version, so empty means it doesn't exist.
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// GetLatestVersion returns the newest version of the named secret.
func (s *Store) GetLatestVersion(name string) (*SecretVersion, error) {
	row := s.db.QueryRow(
		`SELECT v.version, v.ciphertext, v.nonce, v.created_at
		 FROM secrets s
		 JOIN secret_versions v ON v.secret_id = s.id
		 WHERE s.name = ?
		 ORDER BY v.version DESC
		 LIMIT 1`,
		name,
	)
	return scanVersion(row)
}

// GetVersion returns one specific version of the named secret.
func (s *Store) GetVersion(name string, version int) (*SecretVersion, error) {
	row := s.db.QueryRow(
		`SELECT v.version, v.ciphertext, v.nonce, v.created_at
		 FROM secrets s
		 JOIN secret_versions v ON v.secret_id = s.id
		 WHERE s.name = ? AND v.version = ?`,
		name, version,
	)
	return scanVersion(row)
}

func scanVersion(row *sql.Row) (*SecretVersion, error) {
	var sv SecretVersion
	err := row.Scan(&sv.Version, &sv.Ciphertext, &sv.Nonce, &sv.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sv, nil
}