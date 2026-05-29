# aisudo — Build Plan

Step-by-step tasks to go from zero to working v0.1. Each task is small enough to complete in one sitting. Check off with `[x]` as you go.

---

## Phase 0: Project Bootstrap ✅

- [x] 0.1 Initialize Rust project (`cargo init --name aisudo`) in `~/Code/aisudo`
- [x] 0.2 Set up `Cargo.toml` with workspace structure if needed, add core dependencies
- [x] 0.3 Set up `.gitignore` for Rust (target/, *.enc, secrets, etc.)
- [x] 0.4 Create folder structure: `src/daemon/`, `src/cli/`, `src/policy/`, `src/protocol/`, `src/transport/`, `src/grants/`, `src/audit/`, `src/secrets/`, `src/crypto/`, `src/config/`
- [x] 0.5 Create a basic `main.rs` with `clap` subcommand stubs for all v0.1 commands

---

## Phase 1: Config & Directory Layout ✅

- [x] 1.1 Implement `~/.aisudo/` directory creation with correct permissions (`0700` for private/)
- [x] 1.2 Implement config file read/write (`~/.aisudo/config.toml`)
- [x] 1.3 Implement `aisudo init` command — create dirs, prompt for Telegram bot token + chat ID, write config, validate connectivity

---

## Phase 2: Core Data Model ✅

- [x] 2.1 Define `App` struct (name, pid, cwd) with serde
- [x] 2.2 Define `Action` enum (`Exec`, `Secret`, `FileRead`, `FileWrite`, `Network`) with structured metadata per variant
- [x] 2.3 Define `Request` struct (id, created_at, expires_at, app, action, reason, requested_grant, nonce, request_hash)
- [x] 2.4 Define `Decision` enum (`Allow`, `Ask`, `Deny`) + `Severity` enum (`Info`, `Alert`, `Critical`)
- [x] 2.5 Define `Grant` struct (id, created_at, expires_at, app, action, scope, revoked_at)
- [x] 2.6 Define `Device` struct (id, name, public_key, role, capabilities, created_at, last_seen_at, revoked_at)
- [x] 2.7 Define wire protocol messages as serde structs matching PROTOCOL.md JSON schemas

---

## Phase 3: Policy Engine ✅

- [x] 3.1 Define `PolicyRule` struct and `Policy` struct (defaults + rules list) matching POLICY.md TOML format
- [x] 3.2 Implement TOML parsing for policy files
- [x] 3.3 Implement rule matching engine — match action kind, argv patterns (glob), cwd, app name, resource
- [x] 3.4 Implement risk classification — built-in heuristics for package managers, sudo, destructive ops, secret access
- [x] 3.5 Implement `evaluate()` — given request + policy → decision + severity + matched rule + reasons
- [x] 3.6 Create default policy TOML that ships with `aisudo init`
- [x] 3.7 Write unit tests for policy matching and evaluation

---

## Phase 4: Audit Log ✅

- [x] 4.1 Implement append-only JSON lines writer for `~/.aisudo/public/audit.log`
- [x] 4.2 Define `AuditEntry` struct (id, time, app, action, summary, decision, matched_rule, severity)
- [x] 4.3 Implement `aisudo audit tail` — follow mode for the log
- [x] 4.4 Implement `aisudo audit show <req_id>` — find and display a single entry
- [x] 4.5 Write tests for audit log append and read

---

## Phase 5: Grant Engine ✅

- [x] 5.1 Implement grant storage (`~/.aisudo/private/grants.toml`)
- [x] 5.2 Implement grant creation from approved decisions (once, scoped with duration/workspace)
- [x] 5.3 Implement grant lookup — given request, find matching active (non-expired, non-revoked) grant
- [x] 5.4 Implement grant expiry (lazy cleanup on lookup)
- [x] 5.5 Implement `aisudo grants list` and `aisudo grants revoke <id>`
- [x] 5.6 Write tests for grant lifecycle

---

## Phase 6: Secret Registry & Backend ✅

- [x] 6.1 Define `SecretEntry` struct (name, kind, scope, risk, expiry, backend_ref)
- [x] 6.2 Implement secret registry storage (`~/.aisudo/private/secrets.toml`)
- [x] 6.3 Implement macOS Keychain backend via `keyring` crate
- [x] 6.4 Implement in-memory backend for testing
- [x] 6.5 Implement `aisudo ask secret <name>` — lookup secret, evaluate policy, return value or escalate
- [x] 6.6 Implement `aisudo scan` — scan filesystem for exposed secrets (.env, hardcoded tokens)
- [x] 6.7 Write tests for secret registry CRUD and backend read/write

---

## Phase 7: Crypto & Device Pairing ✅

- [x] 7.1 Implement Ed25519 key generation for devices
- [x] 7.2 Implement device registry storage (`~/.aisudo/private/devices.toml`)
- [x] 7.3 Implement pairing code generation (short-lived, random)
- [x] 7.4 Implement `aisudo pair` — generate code, wait for device submission, show fingerprint, confirm
- [x] 7.5 Implement signature creation (device side) and verification (daemon side)
- [x] 7.6 Implement nonce tracking for replay protection
- [x] 7.7 Implement `aisudo devices list` and `aisudo devices revoke <id>`
- [x] 7.8 Write tests for key gen, sign, verify, pair flow

---

## Phase 8: Telegram Transport ✅

- [x] 8.1 Implement Telegram Bot API client (`reqwest` + bot token from config)
- [x] 8.2 Implement notification sending — format approval request with inline keyboard buttons
- [x] 8.3 Implement callback query handler — receive button taps, map to decision
- [x] 8.4 Implement message formatting per TRANSPORTS.md (app, action, risk, no secrets in body)
- [x] 8.5 Write tests for message formatting

---

## Phase 9: Daemon Core ✅

- [x] 9.1 Implement Unix socket listener (`~/.aisudo/aisudo.sock`) with `tokio::net::UnixListener`
- [x] 9.2 Implement request intake — parse JSON messages from socket, validate schema
- [x] 9.3 Implement request lifecycle: pending → evaluate policy → (allow/deny/escalate) → wait for approval → respond
- [x] 9.4 Implement escalation flow — send Telegram notification, wait for callback, apply decision
- [x] 9.5 Implement grant creation on approval
- [x] 9.6 Implement request expiry — timeout pending requests
- [x] 9.7 Wire up audit logging for every request
- [x] 9.8 Implement `aisudo daemon` command — start socket listener + Telegram polling loop
- [x] 9.9 Write integration tests: send request via socket, verify response

---

## Phase 10: CLI Exec & Request ✅

- [x] 10.1 Implement `aisudo exec -- <cmd>` — connect to daemon socket, send exec request, wait for response
- [x] 10.2 If allowed: execute the command with `std::process::Command`, forward stdout/stderr/exit code
- [x] 10.3 If denied: print denial reason, exit non-zero
- [x] 10.4 If escalated: print "waiting for approval…" spinner, block until daemon responds
- [x] 10.5 Implement `aisudo request --json < file` — send raw JSON request, return response
- [x] 10.6 Implement `aisudo requests pending` — list pending requests via socket query
- [x] 10.7 Implement `aisudo request show <req_id>` — get request details + status

---

## Phase 11: Policy Management CLI 🔲

- [x] 11.1 Implement `aisudo policy` — show current active policy
- [ ] 11.2 Implement `aisudo policy propose <file>` — create a proposal from a TOML diff file
- [ ] 11.3 Implement `aisudo policy diff <proposal_id>` — show proposed changes as diff
- [ ] 11.4 Implement `aisudo policy apply <proposal_id>` — apply proposal after human confirmation
- [x] 11.5 Implement `aisudo policy explain <req_id>` — show which rule matched and why

---

## Phase 12: Polish & Integration 🔲

- [x] 12.1 Implement `aisudo status` — show daemon running, device count, grant count, last audit entry
- [ ] 12.2 Implement TUI fallback approval (`ratatui`) — when no transport configured, show local TUI prompt
- [x] 12.3 Add `tracing` structured logging throughout, configurable verbosity
- [ ] 12.4 Add shell completions generation (`clap_complete`)
- [ ] 12.5 Handle graceful shutdown (SIGTERM/SIGINT) for daemon
- [ ] 12.6 Write end-to-end integration test: init → pair (mock) → exec → approve → verify execution

---

## Phase 13: Packaging & Release 🔲

- [ ] 13.1 Update `README.md` usage section with install instructions
- [ ] 13.2 Create GitHub Actions CI (build, test, lint, clippy)
- [ ] 13.3 Create release workflow (cross-compile for macOS arm/x86, Linux x86, Windows)
- [ ] 13.4 Test fresh install flow on clean machine
- [ ] 13.5 Tag v0.1.0 release

---

## Notes

- **Security-sensitive code** — keep dependency count minimal, audit what we pull in.
- **ADR decisions to respect**: secret broker not full gate (ADR-0001), Telegram primary transport (ADR-0002), user-owned bot (ADR-0003).
- **Default-allow** for unknown actions (except secrets → default-ask). This is deliberate per ADR-0001.
- Each phase should compile and pass tests before moving on.

---

## Current Status

**Completed:** Phases 0-10 (62 tests passing)
**Remaining:** Phases 11-13 (policy proposals, TUI, shell completions, CI/CD)

### What Works Today

```bash
# Setup
aisudo init                              # First-run setup with Telegram config

# Daemon
aisudo daemon                            # Start the authorization daemon

# Gate commands
aisudo exec -- pnpm install              # Gate a command execution
aisudo exec -- cargo test                # Will be allowed by default policy

# Request secrets
aisudo ask secret GITHUB_TOKEN           # Request access to a secret

# Policy
aisudo policy                            # Show current policy
aisudo policy explain req_abc123         # Explain why a request was decided

# Devices
aisudo pair                              # Generate pairing code
aisudo devices list                      # List paired devices

# Grants
aisudo grants list                       # List active grants
aisudo grants revoke grant_xyz           # Revoke a grant

# Audit
aisudo audit tail                        # Follow audit log
aisudo audit show req_abc123             # Show specific audit entry

# Scan
aisudo scan                              # Scan for exposed secrets

# Status
aisudo status                            # Show daemon status
```

### Test Summary

```
62 tests passing
├── config: 3 tests
├── protocol: 7 tests
├── policy: 12 tests
├── audit: 5 tests
├── grants: 9 tests
├── secrets: 7 tests
├── crypto: 10 tests
├── transport: 5 tests
├── daemon: 4 tests
└── cli: 1 test
```
