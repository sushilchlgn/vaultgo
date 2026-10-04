CREATE TABLE IF NOT EXISTS secrets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secret_versions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id   INTEGER NOT NULL REFERENCES secrets(id),
    version     INTEGER NOT NULL,
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    key_id      INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (secret_id, version)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    key_hash    TEXT NOT NULL UNIQUE,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  DATETIME
);

CREATE TABLE IF NOT EXISTS key_scopes (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id  INTEGER NOT NULL REFERENCES api_keys(id),
    action  TEXT NOT NULL CHECK (action IN ('read', 'write')),
    pattern TEXT NOT NULL,
    UNIQUE (key_id, action, pattern)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    key_id      INTEGER,
    key_name    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    secret_name TEXT NOT NULL DEFAULT '',
    version     INTEGER,
    status      INTEGER NOT NULL,
    outcome     TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT ''
);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;