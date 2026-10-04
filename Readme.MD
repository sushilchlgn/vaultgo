# vaultgo

A small, self-hosted secrets manager written in Go. It stores sensitive values (API keys, database passwords) encrypted at rest, hands them out over an authenticated HTTPS API, and records every access.

I built it as a learning project to design a security-sensitive backend end to end, and I kept notes on the trade-offs behind each decision (see [Design decisions](#design-decisions-and-trade-offs)).

> **Status:** learning/portfolio project. It has not been security-audited and is not meant for production use.

## Why a secrets manager

Putting a database password in source code or a `.env` file means anyone with the code or the machine can read it, with no record of who looked. A secrets manager moves credentials into a separate service that:

- encrypts them at rest,
- makes every caller prove who it is,
- limits each caller to the secrets it needs,
- and logs every access.

## Features

- **Versioned secrets.** Writing a secret never overwrites a value. Each change appends a new version, so the full history is kept and any version can be read back.
- **Encryption at rest.** Values are encrypted with AES-256-GCM using a fresh random nonce per version. The database only ever holds ciphertext.
- **Master key rotation.** The server holds a keyring of master keys. New data is encrypted under the newest key, older keys can still decrypt, and a `rewrap` command moves existing data onto the newest key so an old key can be retired with no downtime.
- **API key authentication.** Keys are random 256-bit values. Only a SHA-256 hash is stored, and a key is shown exactly once, when it is created.
- **Scoped authorization, deny by default.** A key can do nothing until it is granted scopes such as `read:db-*` or `write:api-token`. Read and write are separate permissions.
- **Append-only audit log.** Every API request is recorded with who, what, which secret and version, outcome, and source IP. Denied requests and failed logins are recorded too, and so are administrative actions run from the command line. Secret values are never logged. Database triggers reject any update or delete of the log.
- **Instant revocation.** Keys are checked against the database on every request, so a revoked key stops working on its very next call.
- **Rate limiting and lockout.** Per-IP request limits, plus a temporary lockout after repeated failed logins. Server timeouts guard against slow-connection attacks.
- **TLS.** HTTPS with TLS 1.2 or newer. The server refuses to listen on a non-loopback address without TLS.
- **Admin through a local CLI.** Creating, granting, revoking and listing keys, and rotating master keys, are done on the machine itself, so there is no remote admin surface.

## How a request flows

```
client
  -> rate limiter       (per-IP limits and failed-login lockout)
  -> router
  -> requireAuth        (valid, non-revoked API key?  else 401)
  -> audit              (records the request and its outcome)
  -> requireScope       (key allowed to do this to this secret?  else 403)
  -> handler            (validate input, encrypt/decrypt, talk to the store)
  -> SQLite
```

The audit layer sits between authentication and authorization on purpose: it knows who the caller is, and it also sees the requests that authorization rejects.

## Quick start

Requires Go 1.22 or newer (the router uses method-and-path patterns).

```powershell
git clone https://github.com/sushilchlgn/vaultgo.git
cd vaultgo
go test ./...
```

**1. Generate a master key** and keep it somewhere safe. Losing it means losing every stored secret.

```powershell
go run . genkey
$env:VAULT_MASTER_KEY = "paste-the-64-character-key-here"
```

A single `VAULT_MASTER_KEY` is treated as key id 1. (Linux or macOS: `export VAULT_MASTER_KEY=$(openssl rand -hex 32)`.)

**2. Create an admin key.** It is printed once, so save it.

```powershell
go run . createkey admin "read:*,write:*"
```

**3. Make a development certificate and start the server with HTTPS.**

```powershell
go run . gencert
$env:VAULT_TLS_CERT = "certs\localhost.crt"
$env:VAULT_TLS_KEY  = "certs\localhost.key"
go run .
```

The server listens on `https://127.0.0.1:8443`. The certificate is self-signed, so clients must be told to trust it (for example `curl --cacert certs/localhost.crt`).

## Rotating the master key

```powershell
go run . genkey                                   # 1. make a new key and store it safely
$env:VAULT_MASTER_KEYS = "2:<new key>,1:<old key>" # 2. new key gets the higher id; unset VAULT_MASTER_KEY
# 3. restart the server: new writes now use key 2, old data still reads via key 1
go run . keystatus                                # 4. see how many versions each key protects
go run . rewrap                                   # 5. re-encrypt everything under key 2
go run . keystatus                                # 6. key 1 should now protect 0 versions
# 7. remove "1:<old key>" from VAULT_MASTER_KEYS and restart
```

`rewrap` works in batches inside transactions. If any version cannot be decrypted (for example because an old key was removed too early), that batch is rolled back and nothing in it changes.

## API

Every endpoint except `/health` needs the header `Authorization: Bearer <api key>`.

| Method | Path | Needs scope | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| POST | `/secrets` | `write` on the new name | Create a secret (body: `name`, `value`) |
| GET | `/secrets/{name}` | `read` | Read the latest version |
| GET | `/secrets/{name}/versions` | `read` | List versions (numbers and timestamps only) |
| GET | `/secrets/{name}/versions/{n}` | `read` | Read one specific version |
| POST | `/secrets/{name}/versions` | `write` | Write a new version (body: `value`) |

Example exchange:

```
POST /secrets
Authorization: Bearer vgo_...
Content-Type: application/json

{"name": "db-password", "value": "hunter2"}

-> 201 {"name": "db-password", "version": 1}
```

Status codes: `401` unknown or missing key, `403` key lacks the scope, `404` secret or version not found, `409` name already exists, `429` rate limited or locked out.

## CLI

| Command | Purpose |
|---|---|
| `go run .` | Start the server |
| `go run . createkey <name> "<scopes>"` | Create an API key with scopes |
| `go run . grant <name> "<scopes>"` | Add scopes to an existing key |
| `go run . revoke <name>` | Disable a key immediately |
| `go run . listkeys` | List API keys, status and scopes |
| `go run . audit [count]` | Show recent audit entries |
| `go run . gencert` | Make a development TLS certificate |
| `go run . genkey` | Generate a new master key |
| `go run . keystatus` | Show how many versions each master key protects |
| `go run . rewrap` | Re-encrypt all versions under the current master key |

Scopes look like `read:db-*,write:db-password`. A pattern is an exact name, a prefix ending in `*`, or just `*`.

Configuration is through environment variables: `VAULT_MASTER_KEY` or `VAULT_MASTER_KEYS` (one of the two), `VAULT_TLS_CERT` and `VAULT_TLS_KEY`, and optionally `VAULT_ADDR`.

## Design decisions and trade-offs

**Versioning from the start.** Secrets and their versions are separate tables, and API writes only ever insert new versions. The next version number is computed inside the INSERT itself, with a `UNIQUE (secret_id, version)` constraint as a backstop, so two concurrent writers cannot silently share a number.

**A keyring instead of a single key.** Each stored version records which master key encrypted it. New data uses the highest key id, and any key in the ring can decrypt. That is what lets old and new keys coexist, so rotation needs no downtime. `rewrap` is the only operation that rewrites existing ciphertext, and the plaintext history stays unchanged.

**Safe rotation.** Rewrapping happens in transactions, one batch at a time, and a failure leaves the batch untouched. A `keystatus` command shows when an old key protects nothing and is safe to retire. A migration adds the `key_id` column to databases created before rotation existed, and a test covers it.

**SHA-256, not bcrypt, for API keys.** Bcrypt exists to slow down guessing of human-chosen passwords. These keys are 256 random bits, so guessing is infeasible regardless, and a fast hash keeps every request cheap.

**401 versus 403, and checking before looking up.** A missing or wrong key gets the same 401 either way. A key without access gets a 403 *before* any database lookup, so it gets the same answer whether or not the secret exists, which stops it probing for names.

**Deny by default and least privilege.** A new key has no scopes. Reading does not imply writing. A leaked narrow key can only do narrow damage.

**Audit log design.** Failed logins and denials are logged because they are the signals of an attack. Blocked requests during a lockout are *not* logged individually, so an attacker cannot fill the disk. Only the start of the lockout is recorded. The log is written after the response, so a failed audit write does not block a request. A stricter design would refuse to return a secret unless its audit record was stored first, trading availability for accountability.

**Availability versus security.** Because apps depend on this service, clients should fetch a secret once and cache it rather than calling on every request. Long cache windows protect users from short outages at the cost of slower revocation. A standing "break-glass" credential would also help during an outage, but it is an unmanaged secret outside all the logging and access control, so I treated it as a documented production discussion point instead of building it.

## Threat model

**Designed to protect against:**

- a stolen database file (values are encrypted, API keys are hashed),
- a leaked API key (scopes limit it, revocation kills it, the audit log shows what it touched),
- brute-force key guessing and request floods,
- eavesdropping on the connection (TLS),
- probing for which secrets exist,
- exposure of a master key *going forward* (rotate it, rewrap, retire the old one).

**Not designed to protect against:**

- an attacker who has both the database *and* a master key, or who can read the server process's memory,
- a master key that leaked *before* rotation: any copy of the old database made earlier is still readable with that old key, and rotation cannot change that,
- anyone with full access to the machine, who could also remove the audit-log triggers,
- a compromised client application that legitimately holds a secret.

## Known limitations

- Master keys live in environment variables. The production approach is envelope encryption: a key management service holds the master key, and each secret gets its own data key.
- Ciphertext is not cryptographically bound to its secret and version (for example through GCM's additional authenticated data), so a database writer could in principle swap ciphertext between rows.
- Rate-limit state lives in memory, so it resets on restart and does not work across multiple instances. Behind a reverse proxy, every client would appear to share the proxy's IP unless a trusted forwarded-IP header is used.
- SQLite on a single node: no high availability.
- Administrative actions are logged, but with no cryptographic protection against someone who controls the machine; real systems ship logs to a separate host.
- No way to delete a secret or a version.
- The TLS certificate from `gencert` is for development only. Production should use a CA-signed certificate or a reverse proxy that terminates TLS.
- No client library yet to handle fetching and caching.

## Project layout

| File | Responsibility |
|---|---|
| `main.go` | Wiring, listen address and TLS decisions |
| `handlers.go` | HTTP handlers and input validation |
| `store.go` | Secrets and versions in the database |
| `crypto.go` | AES-256-GCM, the keyring, and master key loading |
| `rewrap.go` | Re-encrypting stored versions under the current key |
| `keys.go`, `keysadmin.go` | API key creation, validation, revocation, scopes |
| `auth.go`, `authz.go` | Authentication and scope checks |
| `audit.go` | Audit logging |
| `ratelimit.go` | Request limiter and failed-login lockout |
| `tls.go` | Development certificate and loopback check |
| `cli.go` | Command-line administration |
| `db.go`, `schema.sql` | Database setup and migration |

## Tests

```powershell
go test ./...
```

Tests cover encryption (round trip, tamper detection, nonce uniqueness), the keyring (parsing, current-key selection, old data staying readable), rewrapping (including failing safely when an old key is missing), the database migration, scope matching and deny-by-default, the append-only audit log, key revocation, the rate limiter and lockout with a fake clock, and certificate validity.