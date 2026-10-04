package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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

// runAudit prints the most recent audit entries.
func runAudit(limit int) {
	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	entries, err := NewStore(db).RecentAudit(limit)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}

	fmt.Printf("%-20s %-14s %-7s %-16s %-4s %-6s %-16s %s\n",
		"TIME (UTC)", "KEY", "ACTION", "SECRET", "VER", "STATUS", "OUTCOME", "IP")
	for _, e := range entries {
		ver := "-"
		if e.Version != 0 {
			ver = strconv.Itoa(e.Version)
		}
		key := e.KeyName
		if key == "" {
			key = "-"
		}
		secret := e.SecretName
		if secret == "" {
			secret = "-"
		}
		fmt.Printf("%-20s %-14s %-7s %-16s %-4s %-6d %-16s %s\n",
			e.At, key, e.Action, secret, ver, e.Status, e.Outcome, e.IP)
	}
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
		case "audit":
			limit := 20
			if len(os.Args) >= 3 {
				n, err := strconv.Atoi(os.Args[2])
				if err != nil || n < 1 || n > 1000 {
					fmt.Println("usage: go run . audit [count 1-1000]")
					os.Exit(1)
				}
				limit = n
			}
			runAudit(limit)
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