package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
)

// auditInfo is filled in as a request is handled, so the audit record can
// include details only the handler knows (like which version was created).
type auditInfo struct {
	SecretName string
	Version    int
}

type auditCtxKey struct{}

// setAuditSecret lets a handler tell the audit log which secret and version
// a request touched. It does nothing if the request isn't being audited.
func setAuditSecret(ctx context.Context, name string, version int) {
	if info, ok := ctx.Value(auditCtxKey{}).(*auditInfo); ok {
		info.SecretName = name
		info.Version = version
	}
}

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func outcomeFor(status int) string {
	switch {
	case status < 400:
		return "ok"
	case status == http.StatusUnauthorized:
		return "unauthenticated"
	case status == http.StatusForbidden:
		return "denied"
	case status == http.StatusNotFound:
		return "not_found"
	case status < 500:
		return "rejected"
	default:
		return "error"
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AuditEntry is one row of the audit log, for display.
type AuditEntry struct {
	At         string
	KeyName    string
	Action     string
	SecretName string
	Version    int // 0 means not applicable
	Status     int
	Outcome    string
	IP         string
}

// WriteAudit appends one record. It never stores secret values.
func (s *Store) WriteAudit(keyID int64, keyName, action, secretName string, version, status int, outcome, ip string) error {
	var kid, ver any // nil becomes NULL in the database
	if keyID != 0 {
		kid = keyID
	}
	if version != 0 {
		ver = version
	}

	_, err := s.db.Exec(
		`INSERT INTO audit_log (key_id, key_name, action, secret_name, version, status, outcome, ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		kid, truncate(keyName, 100), action, truncate(secretName, 100), ver, status, outcome, ip,
	)
	return err
}

// RecentAudit returns the newest entries first.
func (s *Store) RecentAudit(limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(
		`SELECT at, key_name, action, secret_name, COALESCE(version, 0), status, outcome, ip
		 FROM audit_log ORDER BY id DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.At, &e.KeyName, &e.Action, &e.SecretName, &e.Version, &e.Status, &e.Outcome, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// audit wraps a handler and records every request after it completes.
// It must sit INSIDE requireAuth so the caller is known, and OUTSIDE
// requireScope so that denied requests are recorded too.
func (s *Server) audit(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := &auditInfo{SecretName: r.PathValue("name")}
		if v, err := strconv.Atoi(r.PathValue("version")); err == nil {
			info.Version = v
		}

		r = r.WithContext(context.WithValue(r.Context(), auditCtxKey{}, info))
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next(rec, r)

		caller, _ := callerFromContext(r.Context())
		err := s.store.WriteAudit(
			caller.ID, caller.Name, action,
			info.SecretName, info.Version,
			rec.status, outcomeFor(rec.status), clientIP(r),
		)
		if err != nil {
			log.Printf("audit write failed: %v", err)
		}
	}
}

// rejectUnauthorized records a failed login attempt, then sends the 401.
func (s *Server) rejectUnauthorized(w http.ResponseWriter, r *http.Request) {
	err := s.store.WriteAudit(0, "", "auth", "", 0, http.StatusUnauthorized, "unauthenticated", clientIP(r))
	if err != nil {
		log.Printf("audit write failed: %v", err)
	}
	unauthorized(w)
}