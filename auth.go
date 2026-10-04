package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
)

type Caller struct {
	ID   int64
	Name string
}

type ctxKey struct{}

// callerFromContext returns the authenticated caller for a request.
// The audit logging step will use this.
func callerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// requireAuth wraps a handler so it only runs for requests carrying a valid
// "Authorization: Bearer <key>" header.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "

		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			unauthorized(w)
			return
		}

		key := strings.TrimSpace(strings.TrimPrefix(h, prefix))
		if key == "" {
			unauthorized(w)
			return
		}

		id, name, err := s.store.ValidateAPIKey(key)
		if errors.Is(err, ErrInvalidKey) {
			// Same response as "missing", so attackers learn nothing.
			unauthorized(w)
			return
		}
		if err != nil {
			log.Printf("validate key: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		ctx := context.WithValue(r.Context(), ctxKey{}, Caller{ID: id, Name: name})
		next(w, r.WithContext(ctx))
	}
}