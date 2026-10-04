package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
)

type Caller struct {
	ID     int64
	Name   string
	Scopes []Scope
}

type ctxKey struct{}

// callerFromContext returns the authenticated caller for a request.
func callerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// requireAuth wraps a handler so it only runs for requests carrying a valid
// "Authorization: Bearer <key>" header. It also loads the caller's scopes.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "

		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			s.rejectUnauthorized(w, r)
			return
		}

		key := strings.TrimSpace(strings.TrimPrefix(h, prefix))
		if key == "" {
			s.rejectUnauthorized(w, r)
			return
		}

		id, name, err := s.store.ValidateAPIKey(key)
		if errors.Is(err, ErrInvalidKey) {
			// Same response as "missing", so attackers learn nothing.
			s.rejectUnauthorized(w, r)
			return
		}
		if err != nil {
			log.Printf("validate key: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		scopes, err := s.store.LoadScopes(id)
		if err != nil {
			log.Printf("load scopes: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		caller := Caller{ID: id, Name: name, Scopes: scopes}
		ctx := context.WithValue(r.Context(), ctxKey{}, caller)
		next(w, r.WithContext(ctx))
	}
}