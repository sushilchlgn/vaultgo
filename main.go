package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// runCreateKey is the bootstrap path: only someone with access to the
// machine can mint a key, so there is no open "create key" endpoint.
func runCreateKey(name string) {
	if !validName.MatchString(name) {
		fmt.Println("name must be 1-100 characters: letters, digits, '.', '_' or '-'")
		os.Exit(1)
	}

	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	key, err := NewStore(db).CreateAPIKey(name)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}

	fmt.Println("API key created for:", name)
	fmt.Println()
	fmt.Println(key)
	fmt.Println()
	fmt.Println("Save it now. It is shown only once and cannot be recovered.")
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "createkey" {
		if len(os.Args) != 3 {
			fmt.Println("usage: go run . createkey <name>")
			os.Exit(1)
		}
		runCreateKey(os.Args[2])
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

	// Health stays open so monitoring can reach it.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Everything that touches secrets requires a valid API key.
	mux.HandleFunc("POST /secrets", srv.requireAuth(srv.handleCreateSecret))
	mux.HandleFunc("GET /secrets/{name}", srv.requireAuth(srv.handleGetSecret))
	mux.HandleFunc("POST /secrets/{name}/versions", srv.requireAuth(srv.handleAddVersion))
	mux.HandleFunc("GET /secrets/{name}/versions", srv.requireAuth(srv.handleListVersions))
	mux.HandleFunc("GET /secrets/{name}/versions/{version}", srv.requireAuth(srv.handleGetSecretVersion))

	// Localhost only for now. Authentication exists, but we are not exposing
	// this to a network until TLS is in place.
	addr := "127.0.0.1:8080"
	log.Printf("vaultgo listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}