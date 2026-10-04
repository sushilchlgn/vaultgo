package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strconv"
)

type Server struct {
	store   *Store
	keyring *Keyring
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,100}$`)

type createSecretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type addVersionRequest struct {
	Value string `json:"value"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	// Limit the request body to 1 MB so nobody can exhaust memory.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req createSecretRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if !validName.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "name must be 1-100 characters: letters, digits, '.', '_' or '-'")
		return
	}

	// The name is in the body, so tell the audit log now. That way even a
	// denied attempt records which secret the caller was after.
	setAuditSecret(r.Context(), req.Name, 0)

	// The scope check happens here instead of in requireScope, for the
	// same reason: the name isn't in the URL.
	caller, _ := callerFromContext(r.Context())
	if !caller.Allowed("write", req.Name) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	ciphertext, nonce, keyID, err := s.keyring.Encrypt([]byte(req.Value))
	if err != nil {
		log.Printf("encrypt: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	version, err := s.store.CreateSecret(req.Name, ciphertext, nonce, keyID)
	if errors.Is(err, ErrSecretExists) {
		writeError(w, http.StatusConflict, "a secret with that name already exists")
		return
	}
	if err != nil {
		log.Printf("create secret: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	setAuditSecret(r.Context(), req.Name, version)

	// Never echo the value back.
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":    req.Name,
		"version": version,
	})
}

// handleAddVersion writes a new version of an existing secret (rotate).
func (s *Server) handleAddVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid secret name")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req addVersionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}

	ciphertext, nonce, keyID, err := s.keyring.Encrypt([]byte(req.Value))
	if err != nil {
		log.Printf("encrypt: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	version, err := s.store.AddVersion(name, ciphertext, nonce, keyID)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		log.Printf("add version: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	setAuditSecret(r.Context(), name, version)

	writeJSON(w, http.StatusCreated, map[string]any{
		"name":    name,
		"version": version,
	})
}

// handleListVersions lists version numbers and timestamps, never values.
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid secret name")
		return
	}

	versions, err := s.store.ListVersions(name)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		log.Printf("list versions: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":     name,
		"versions": versions,
	})
}

// handleGetSecret returns the latest version of a secret.
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid secret name")
		return
	}

	sv, err := s.store.GetLatestVersion(name)
	s.respondWithVersion(w, r, name, sv, err)
}

// handleGetSecretVersion returns one specific version of a secret.
func (s *Server) handleGetSecretVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid secret name")
		return
	}

	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		writeError(w, http.StatusBadRequest, "version must be a positive integer")
		return
	}

	sv, err := s.store.GetVersion(name, version)
	s.respondWithVersion(w, r, name, sv, err)
}

// respondWithVersion decrypts a stored version and writes it as JSON.
func (s *Server) respondWithVersion(w http.ResponseWriter, r *http.Request, name string, sv *SecretVersion, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret or version not found")
		return
	}
	if err != nil {
		log.Printf("read secret: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	plaintext, err := s.keyring.Decrypt(sv.KeyID, sv.Ciphertext, sv.Nonce)
	if err != nil {
		// Wrong key, a key missing from the ring, or tampered data.
		// Log it, but tell the client nothing.
		log.Printf("decrypt %q v%d (key %d): %v", name, sv.Version, sv.KeyID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Record exactly which version was handed out, including for "latest".
	setAuditSecret(r.Context(), name, sv.Version)

	// Secrets must never be cached by browsers or proxies.
	w.Header().Set("Cache-Control", "no-store")

	writeJSON(w, http.StatusOK, map[string]any{
		"name":       name,
		"version":    sv.Version,
		"value":      string(plaintext),
		"created_at": sv.CreatedAt,
	})
}