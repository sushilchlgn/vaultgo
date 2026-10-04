package main

import (
	"log"
	"net/http"
)

func main() {
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

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /secrets", srv.handleCreateSecret)
	mux.HandleFunc("GET /secrets/{name}", srv.handleGetSecret)
	mux.HandleFunc("GET /secrets/{name}/versions/{version}", srv.handleGetSecretVersion)

	// Localhost only until authentication exists.
	addr := "127.0.0.1:8080"
	log.Printf("vaultgo listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}