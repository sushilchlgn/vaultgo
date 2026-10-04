package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Scope grants one action on secrets whose names match the pattern.
// A pattern is an exact name, a prefix ending in "*", or just "*".
type Scope struct {
	Action  string // "read" or "write"
	Pattern string
}

var validPattern = regexp.MustCompile(`^([a-zA-Z0-9._-]{1,100}\*?|\*)$`)

// parseScope turns "read:db-*" into a Scope.
func parseScope(s string) (Scope, error) {
	action, pattern, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return Scope{}, fmt.Errorf("scope %q must look like action:pattern", s)
	}
	if action != "read" && action != "write" {
		return Scope{}, fmt.Errorf("scope %q: action must be read or write", s)
	}
	if !validPattern.MatchString(pattern) {
		return Scope{}, fmt.Errorf("scope %q: invalid pattern", s)
	}
	return Scope{Action: action, Pattern: pattern}, nil
}

// parseScopes parses a comma-separated list like "read:db-*,write:db-password".
func parseScopes(csv string) ([]Scope, error) {
	var out []Scope
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		sc, err := parseScope(part)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	return out, nil
}

func patternMatches(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// Allowed reports whether the caller may perform action on the named secret.
// With no matching scope the answer is no: deny by default.
func (c Caller) Allowed(action, name string) bool {
	for _, sc := range c.Scopes {
		if sc.Action == action && patternMatches(sc.Pattern, name) {
			return true
		}
	}
	return false
}

// requireScope wraps a handler for routes with a {name} in the path.
// It runs BEFORE any database lookup, so a caller without access gets the
// same 403 whether or not the secret exists. That stops them probing for names.
func (s *Server) requireScope(action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := callerFromContext(r.Context())
		if !ok {
			unauthorized(w)
			return
		}
		if !caller.Allowed(action, r.PathValue("name")) {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}