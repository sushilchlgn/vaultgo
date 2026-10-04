package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	// Subcommands (createkey, grant, revoke, listkeys, audit) run and exit.
	if runCommand(os.Args[1:]) {
		return
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

	srv := &Server{
		store:   NewStore(db),
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

	// Localhost only for now. We are not exposing this to a network until
	// TLS is in place.
	addr := "127.0.0.1:8080"
	log.Printf("vaultgo listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}