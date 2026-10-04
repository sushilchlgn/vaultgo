package main

import (
	"database/sql"
	"errors"
	"fmt"
)

type rewrapRow struct {
	ID         int64
	KeyID      int
	Ciphertext []byte
	Nonce      []byte
}

// versionsNotUsing returns up to `limit` versions encrypted under any key
// other than keyID.
func (s *Store) versionsNotUsing(keyID, limit int) ([]rewrapRow, error) {
	rows, err := s.db.Query(
		`SELECT id, key_id, ciphertext, nonce FROM secret_versions
		 WHERE key_id != ? ORDER BY id LIMIT ?`,
		keyID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rewrapRow
	for rows.Next() {
		var r rewrapRow
		if err := rows.Scan(&r.ID, &r.KeyID, &r.Ciphertext, &r.Nonce); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountByKey returns how many stored versions each key id protects.
func (s *Store) CountByKey() (map[int]int, error) {
	rows, err := s.db.Query(`SELECT key_id, COUNT(*) FROM secret_versions GROUP BY key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int]int)
	for rows.Next() {
		var id, n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// rewrapBatch re-encrypts one batch inside a transaction. The WHERE clause
// includes the old key id, so a row that already changed is never touched twice.
func rewrapBatch(tx *sql.Tx, kr *Keyring, rows []rewrapRow) (int, error) {
	done := 0
	for _, r := range rows {
		plaintext, err := kr.Decrypt(r.KeyID, r.Ciphertext, r.Nonce)
		if err != nil {
			return done, fmt.Errorf("version row %d (key %d): %w", r.ID, r.KeyID, err)
		}

		ciphertext, nonce, newID, err := kr.Encrypt(plaintext)
		if err != nil {
			return done, err
		}

		res, err := tx.Exec(
			`UPDATE secret_versions SET ciphertext = ?, nonce = ?, key_id = ?
			 WHERE id = ? AND key_id = ?`,
			ciphertext, nonce, newID, r.ID, r.KeyID,
		)
		if err != nil {
			return done, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return done, err
		}
		done += int(n)
	}
	return done, nil
}

// Rewrap re-encrypts every version that is not under the current key and
// returns how many it changed. Each batch is all-or-nothing: if any row in
// a batch cannot be decrypted (for example its key was removed from the
// ring too early), the batch is rolled back and nothing in it changes.
func Rewrap(s *Store, kr *Keyring) (int, error) {
	const batchSize = 100
	total := 0

	for {
		rows, err := s.versionsNotUsing(kr.CurrentID(), batchSize)
		if err != nil {
			return total, err
		}
		if len(rows) == 0 {
			return total, nil
		}

		tx, err := s.db.Begin()
		if err != nil {
			return total, err
		}

		done, err := rewrapBatch(tx, kr, rows)
		if err != nil {
			tx.Rollback()
			return total, err
		}
		if err := tx.Commit(); err != nil {
			return total, err
		}

		total += done
		if done == 0 {
			return total, errors.New("rewrap made no progress; run it again")
		}
	}
}