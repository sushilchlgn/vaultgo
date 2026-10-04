package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// Subcommands (createkey, grant, revoke, listkeys, audit, gencert)
	// run and exit.
	if runCommand(os.Args[1:]) {
		return
	}

	// Decide how to listen BEFORE touching anything else, and fail closed.
	certFile := os.Getenv("VAULT_TLS_CERT")
	keyFile := os.Getenv("VAULT_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		log.Fatal("set both VAULT_TLS_CERT and VAULT_TLS_KEY, or neither")
	}
	useTLS := certFile != ""

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		if useTLS {
			addr = "127.0.0.1:8443"
		} else {
			addr = "127.0.0.1:8080"
		}
	}
	if !useTLS && !isLoopbackAddr(addr) {
		log.Fatalf("refusing to listen on %s without TLS: set VAULT_TLS_CERT and VAULT_TLS_KEY, or bind to a loopback address", addr)
	}

	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()
	log.Println("database ready")

	key, err := loadMasterKey()
	if err != nil {
		log.Fatalf("master key: %v", err)
	}
	crypter, err := NewCrypter(key)
	if err != nil {
		log.Fatalf("crypto: %v", err)
	}
	log.Println("encryption ready")

	store := NewStore(db)
	srv := &Server{
		store:   store,
		crypter: crypter,
	}

	mux := http.NewServeMux()

	// Health stays open so monitoring can reach it. It is not audited,
	// because monitoring hits it constantly and it exposes nothing.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Layers, outermost first:
	//   requireAuth  - who are you? (failed attempts are audited)
	//   audit        - record the request and its outcome
	//   requireScope - are you allowed? (denials are audited)
	mux.HandleFunc("POST /secrets",
		srv.requireAuth(srv.audit("create", srv.handleCreateSecret)))
	mux.HandleFunc("GET /secrets/{name}",
		srv.requireAuth(srv.audit("read", srv.requireScope("read", srv.handleGetSecret))))
	mux.HandleFunc("POST /secrets/{name}/versions",
		srv.requireAuth(srv.audit("rotate", srv.requireScope("write", srv.handleAddVersion))))
	mux.HandleFunc("GET /secrets/{name}/versions",
		srv.requireAuth(srv.audit("list", srv.requireScope("read", srv.handleListVersions))))
	mux.HandleFunc("GET /secrets/{name}/versions/{version}",
		srv.requireAuth(srv.audit("read", srv.requireScope("read", srv.handleGetSecretVersion))))

	// Rate limiting wraps the entire router, so it applies to every route
	// and rejects abusive clients before any database work happens.
	handler := rateLimit(store, NewLimits(), mux)

	// Timeouts defend against slow-connection attacks that hold sockets open.
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	if useTLS {
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Printf("vaultgo listening on https://%s", addr)
		if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatal(err)
		}
		return
	}

	log.Printf("vaultgo listening on http://%s (no TLS, loopback only)", addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}