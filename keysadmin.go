package main

// KeyInfo describes one API key for display. It never includes the key itself.
type KeyInfo struct {
	Name      string
	CreatedAt string
	RevokedAt string // empty if the key is still active
	Scopes    string
}

// RevokeKey disables an active key by name. It takes effect on the very
// next request, because every request validates the key against the database.
func (s *Store) RevokeKey(name string) error {
	res, err := s.db.Exec(
		`UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP
		 WHERE name = ? AND revoked_at IS NULL`,
		name,
	)
	if err != nil {
		return err
	}

	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListKeys returns every key with its scopes, oldest first.
func (s *Store) ListKeys() ([]KeyInfo, error) {
	rows, err := s.db.Query(
		`SELECT k.name,
		        k.created_at,
		        COALESCE(k.revoked_at, ''),
		        COALESCE(group_concat(sc.action || ':' || sc.pattern, ','), '')
		 FROM api_keys k
		 LEFT JOIN key_scopes sc ON sc.key_id = k.id
		 GROUP BY k.id
		 ORDER BY k.id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []KeyInfo
	for rows.Next() {
		var ki KeyInfo
		if err := rows.Scan(&ki.Name, &ki.CreatedAt, &ki.RevokedAt, &ki.Scopes); err != nil {
			return nil, err
		}
		out = append(out, ki)
	}
	return out, rows.Err()
}