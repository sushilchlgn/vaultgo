package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
)

// runCreateKey is the bootstrap path: only someone with access to the
// machine can mint a key, so there is no open "create key" endpoint.
func runCreateKey(name, scopeArg string) {
	if !validName.MatchString(name) {
		fmt.Println("name must be 1-100 characters: letters, digits, '.', '_' or '-'")
		os.Exit(1)
	}

	scopes, err := parseScopes(scopeArg)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	key, err := NewStore(db).CreateAPIKey(name, scopes)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}

	fmt.Println("API key created for:", name)
	fmt.Println("Scopes:", scopeArg)
	fmt.Println()
	fmt.Println(key)
	fmt.Println()
	fmt.Println("Save it now. It is shown only once and cannot be recovered.")
}

// runGrant adds scopes to an existing key.
func runGrant(keyName, scopeArg string) {
	scopes, err := parseScopes(scopeArg)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	err = NewStore(db).GrantScopes(keyName, scopes)
	if errors.Is(err, ErrNotFound) {
		fmt.Println("no active key named", keyName)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("grant: %v", err)
	}

	fmt.Println("Granted", scopeArg, "to", keyName)
}

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "createkey":
			if len(os.Args) != 4 {
				fmt.Println(`usage: go run . createkey <name> "<scopes>"`)
				fmt.Println(`example: go run . createkey app1 "read:db-*,write:db-password"`)
				os.Exit(1)
			}
			runCreateKey(os.Args[2], os.Args[3])
			return
		case "grant":
			if len(os.Args) != 4 {
				fmt.Println(`usage: go run . grant <keyname> "<scopes>"`)
				os.Exit(1)
			}
			runGrant(os.Args[2], os.Args[3])
			return
		}
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

	// Every secrets route needs a valid key (authentication), and then a
	// scope that covers this secret and action (authorization).
	mux.HandleFunc("POST /secrets",
		srv.requireAuth(srv.handleCreateSecret)) // scope checked inside the handler
	mux.HandleFunc("GET /secrets/{name}",
		srv.requireAuth(srv.requireScope("read", srv.handleGetSecret)))
	mux.HandleFunc("POST /secrets/{name}/versions",
		srv.requireAuth(srv.requireScope("write", srv.handleAddVersion)))
	mux.HandleFunc("GET /secrets/{name}/versions",
		srv.requireAuth(srv.requireScope("read", srv.handleListVersions)))
	mux.HandleFunc("GET /secrets/{name}/versions/{version}",
		srv.requireAuth(srv.requireScope("read", srv.handleGetSecretVersion)))

	// Localhost only for now. We are not exposing this to a network until
	// TLS is in place.
	addr := "127.0.0.1:8080"
	log.Printf("vaultgo listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}