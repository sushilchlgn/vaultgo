package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
)

const usage = `usage:
  go run .                              start the server
  go run . createkey <name> "<scopes>"  create an API key
  go run . grant <name> "<scopes>"      add scopes to a key
  go run . revoke <name>                disable a key immediately
  go run . listkeys                     list all keys
  go run . audit [count]                show recent audit entries

scopes look like: "read:db-*,write:db-password"`

// openStore opens the database for a command-line command.
func openStore() (*Store, func()) {
	db, err := openDB("vault.db")
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	return NewStore(db), func() { db.Close() }
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
	default:
		fmt.Println(usage)
		os.Exit(1)
	}
	return true
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

	fmt.Println("Revoked", keyName, "- it stops working on the next request.")
	fmt.Println("The name stays taken; create a replacement under a new name.")
}

// runListKeys prints every key and its scopes.
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

// runAudit prints the most recent audit entries.
func runAudit(limit int) {
	store, closeDB := openStore()
	defer closeDB()

	entries, err := store.RecentAudit(limit)
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