package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
)

const usage = `usage:
  go run .                              start the server
  go run . createkey <name> "<scopes>"  create an API key
  go run . grant <name> "<scopes>"      add scopes to a key
  go run . revoke <name>                disable a key immediately
  go run . listkeys                     list all API keys
  go run . audit [count]                show recent audit entries
  go run . gencert                      make a development TLS certificate
  go run . genkey                       generate a new master key
  go run . keystatus                    show how many versions each master key protects
  go run . rewrap                       re-encrypt all versions under the current master key

scopes look like: "read:db-*,write:db-password"

environment:
  VAULT_MASTER_KEY   one master key, 64 hex characters (treated as key id 1)
  VAULT_MASTER_KEYS  several keys: "2:<hex>,1:<hex>" (highest id is current)
  VAULT_TLS_CERT     path to a TLS certificate (enables HTTPS with VAULT_TLS_KEY)
  VAULT_TLS_KEY      path to the matching private key
  VAULT_ADDR         listen address (default 127.0.0.1:8443 with TLS, 127.0.0.1:8080 without)`

// openStore opens the database for a command-line command.
func openStore() (*Store, func()) {
	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	return NewStore(db), func() { db.Close() }
}

// auditCLI records an administrative action. These run on the machine
// itself, so there is no API caller or remote address.
func auditCLI(store *Store, action, target string) {
	if err := store.WriteAudit(0, "(cli)", action, target, 0, 200, "ok", "local"); err != nil {
		log.Printf("audit write failed: %v", err)
	}
}

// runCommand handles command-line subcommands. It returns false when there
// are no arguments, meaning the caller should start the server.
func runCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}

	switch args[0] {
	case "createkey":
		if len(args) != 3 {
			fmt.Println(usage)
			os.Exit(1)
		}
		runCreateKey(args[1], args[2])
	case "grant":
		if len(args) != 3 {
			fmt.Println(usage)
			os.Exit(1)
		}
		runGrant(args[1], args[2])
	case "revoke":
		if len(args) != 2 {
			fmt.Println(usage)
			os.Exit(1)
		}
		runRevoke(args[1])
	case "listkeys":
		runListKeys()
	case "audit":
		limit := 20
		if len(args) >= 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 || n > 1000 {
				fmt.Println("count must be a number from 1 to 1000")
				os.Exit(1)
			}
			limit = n
		}
		runAudit(limit)
	case "gencert":
		runGenCert()
	case "genkey":
		runGenKey()
	case "keystatus":
		runKeyStatus()
	case "rewrap":
		runRewrap()
	default:
		fmt.Println(usage)
		os.Exit(1)
	}
	return true
}

// runGenCert makes a development certificate in ./certs.
func runGenCert() {
	certPath, keyPath, err := generateSelfSignedCert("certs")
	if err != nil {
		log.Fatalf("gencert: %v", err)
	}

	fmt.Println("Development certificate created (valid for 1 year, for localhost only):")
	fmt.Println("  certificate:", certPath)
	fmt.Println("  private key:", keyPath)
	fmt.Println()
	fmt.Println("Keep the certs folder out of git. To start the server with HTTPS:")
	fmt.Printf("  $env:VAULT_TLS_CERT = %q\n", certPath)
	fmt.Printf("  $env:VAULT_TLS_KEY  = %q\n", keyPath)
	fmt.Println("  go run .")
}

// runGenKey prints a fresh random master key. It does not store it anywhere.
func runGenKey() {
	k, err := generateKeyHex()
	if err != nil {
		log.Fatalf("genkey: %v", err)
	}
	fmt.Println(k)
	fmt.Println()
	fmt.Println("Save it in a password manager BEFORE using it. Losing a master key")
	fmt.Println("means losing every secret encrypted under it.")
}

// runKeyStatus shows how many stored versions each master key protects.
// When a retired key reaches zero, it is safe to remove from the keyring.
func runKeyStatus() {
	store, closeDB := openStore()
	defer closeDB()

	counts, err := store.CountByKey()
	if err != nil {
		log.Fatalf("keystatus: %v", err)
	}
	if len(counts) == 0 {
		fmt.Println("no secrets stored yet")
		return
	}

	ids := make([]int, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	for _, id := range ids {
		fmt.Printf("key %d: %d version(s)\n", id, counts[id])
	}
}

// runRewrap re-encrypts everything under the current (highest id) key.
func runRewrap() {
	kr, err := loadKeyring()
	if err != nil {
		log.Fatalf("master key: %v", err)
	}

	store, closeDB := openStore()
	defer closeDB()

	fmt.Printf("Re-encrypting under key id %d (%d key(s) loaded)...\n", kr.CurrentID(), kr.Size())

	total, err := Rewrap(store, kr)
	if err != nil {
		fmt.Printf("stopped after %d version(s): %v\n", total, err)
		fmt.Println("Nothing in the failed batch was changed. Make sure every older key is still in VAULT_MASTER_KEYS.")
		os.Exit(1)
	}

	auditCLI(store, "rewrap", fmt.Sprintf("%d versions", total))
	fmt.Printf("Re-encrypted %d version(s).\n", total)
}

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

	store, closeDB := openStore()
	defer closeDB()

	key, err := store.CreateAPIKey(name, scopes)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}
	auditCLI(store, "createkey", name)

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

	store, closeDB := openStore()
	defer closeDB()

	err = store.GrantScopes(keyName, scopes)
	if errors.Is(err, ErrNotFound) {
		fmt.Println("no active key named", keyName)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("grant: %v", err)
	}
	auditCLI(store, "grant", keyName)

	fmt.Println("Granted", scopeArg, "to", keyName)
}

// runRevoke disables a key.
func runRevoke(keyName string) {
	store, closeDB := openStore()
	defer closeDB()

	err := store.RevokeKey(keyName)
	if errors.Is(err, ErrNotFound) {
		fmt.Println("no active key named", keyName)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("revoke: %v", err)
	}
	auditCLI(store, "revoke", keyName)

	fmt.Println("Revoked", keyName, "- it stops working on the next request.")
	fmt.Println("The name stays taken; create a replacement under a new name.")
}

// runListKeys prints every API key and its scopes.
func runListKeys() {
	store, closeDB := openStore()
	defer closeDB()

	keys, err := store.ListKeys()
	if err != nil {
		log.Fatalf("list keys: %v", err)
	}

	fmt.Printf("%-16s %-9s %-22s %s\n", "NAME", "STATUS", "CREATED", "SCOPES")
	for _, k := range keys {
		status := "active"
		if k.RevokedAt != "" {
			status = "REVOKED"
		}
		scopes := k.Scopes
		if scopes == "" {
			scopes = "(none)"
		}
		fmt.Printf("%-16s %-9s %-22s %s\n", k.Name, status, k.CreatedAt, scopes)
	}
}

// runAudit prints the most recent audit entries. For administrative
// actions, the SECRET column holds the target (a key name, or a count).
func runAudit(limit int) {
	store, closeDB := openStore()
	defer closeDB()

	entries, err := store.RecentAudit(limit)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}

	fmt.Printf("%-20s %-14s %-9s %-16s %-4s %-6s %-16s %s\n",
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
		fmt.Printf("%-20s %-14s %-9s %-16s %-4s %-6d %-16s %s\n",
			e.At, key, e.Action, secret, ver, e.Status, e.Outcome, e.IP)
	}
}