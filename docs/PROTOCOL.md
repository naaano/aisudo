# Protocol

## 1. Device Pairing

### 1.1 Pairing goals

Pairing should be:

- Explicit
- Per-device
- Revocable
- Visible in audit logs
- Protected by local human confirmation or an existing trusted device

### 1.2 Pairing flow

Command:

```bash
aisudo pair
```

Output:

```
Pair new authorizer device

Code: 482-119
Expires: 2 minutes

Scan QR code:
aisudo://pair?code=482-119&host=...
```

Phone/PWA generates a key pair and submits:

```json
{
  "type": "aisudo.pair.v1",
  "pair_code": "482-119",
  "device_name": "Hernan iPhone",
  "public_key": "base64...",
  "capabilities": ["approve", "deny", "view_own_history"]
}
```

Daemon shows local confirmation:

```
Pair device?

Name: Hernan iPhone
Fingerprint: SHA256:ab:13:...

Approve? y/N
```

Or, if already configured, require approval from an existing owner device.

### 1.3 Device record

```json
{
  "id": "device_01j...",
  "name": "Hernan iPhone",
  "public_key": "base64...",
  "role": "owner",
  "capabilities": {
    "approve_risk": ["low", "medium", "high"],
    "change_policy": true,
    "view_full_audit": true,
    "view_policy": true,
    "view_secrets": false
  },
  "created_at": "2026-05-29T04:00:00Z",
  "last_seen_at": null,
  "revoked_at": null
}
```

---

## 2. Local Socket API

### 2.1 Unix socket path

| Platform | Path |
|---|---|
| macOS / Linux | `~/.aisudo/aisudo.sock` |
| Windows | `\\.\pipe\aisudo` |

### 2.2 Request message

```json
{
  "type": "aisudo.request.v1",
  "app": {
    "name": "claude-code",
    "pid": 12345,
    "cwd": "/Users/hernan/dev/my_app"
  },
  "action": {
    "kind": "exec",
    "argv": ["pnpm", "install"],
    "cwd": "/Users/hernan/dev/my_app",
    "env_requested": [],
    "stdin_summary": null
  },
  "reason": "Install dependencies required by the project",
  "requested_grant": {
    "mode": "once"
  }
}
```

### 2.3 Immediate response

**Escalated (human approval needed):**

```json
{
  "type": "aisudo.response.v1",
  "status": "escalated",
  "request_id": "req_01j...",
  "message": "Human approval required"
}
```

**Allowed by policy:**

```json
{
  "type": "aisudo.response.v1",
  "status": "allowed",
  "grant_id": "grant_01j...",
  "message": "Allowed by policy"
}
```

**Denied by policy:**

```json
{
  "type": "aisudo.response.v1",
  "status": "denied",
  "reason": "Access to ~/.ssh is denied"
}
```

---

## 3. Request Model

### 3.1 Approval request

```json
{
  "version": 1,
  "request_id": "req_01j...",
  "created_at": "2026-05-29T04:00:00Z",
  "expires_at": "2026-05-29T04:05:00Z",
  "app": {
    "name": "claude-code",
    "pid": 12345,
    "cwd": "/Users/hernan/dev/my_app"
  },
  "action": {
    "kind": "exec",
    "argv": ["pnpm", "install"],
    "cwd": "/Users/hernan/dev/my_app"
  },
  "risk": {
    "level": "high",
    "reasons": [
      "package manager execution",
      "may execute lifecycle scripts",
      "network access likely"
    ],
    "recommendation": "ask"
  },
  "requested_grant": {
    "mode": "once"
  },
  "nonce": "base64-random",
  "request_hash": "sha256:..."
}
```

### 3.2 Decision message

```json
{
  "type": "aisudo.decision.v1",
  "request_id": "req_01j...",
  "decision": "approve_once",
  "device_id": "device_01j...",
  "request_hash": "sha256:...",
  "created_at": "2026-05-29T04:01:00Z",
  "expires_at": "2026-05-29T04:03:00Z",
  "signature": "base64..."
}
```

### 3.3 Decision values

```
deny
approve_once
approve_for_duration
approve_for_workspace
approve_exact_action_always
approve_policy_proposal
```

---

## 4. Grants

Grants are temporary or scoped auto-approvals.

### 4.1 Grant examples

```
Allow claude-code to run `mix test` in this repo.
Allow cursor to read GITHUB_TOKEN for 10 minutes.
Allow kilo to run `pnpm install` once.
Allow hermes to call GitHub PR API for this repo today.
```

### 4.2 Grant record

```json
{
  "id": "grant_01j...",
  "created_at": "2026-05-29T04:00:00Z",
  "expires_at": "2026-05-29T04:30:00Z",
  "created_by_device": "device_01j...",
  "app": "claude-code",
  "action": {
    "kind": "exec",
    "argv_hash": "sha256:...",
    "cwd": "/Users/hernan/dev/my_app"
  },
  "scope": {
    "workspace": "/Users/hernan/dev/my_app",
    "exact_action_only": true
  },
  "revoked_at": null
}
```

### 4.3 Grant commands

```bash
aisudo grants list
aisudo grants revoke GRANT_ID
aisudo grants revoke --app claude-code
aisudo grants revoke --all
```

---

## 5. Secret Access

`aisudo` can broker secrets without revealing all secrets to agents.

### 5.1 Secret request

```bash
aisudo ask secret GITHUB_TOKEN
```

Or via JSON:

```json
{
  "type": "aisudo.request.v1",
  "action": {
    "kind": "secret",
    "resource": "GITHUB_TOKEN",
    "purpose": "Create a pull request"
  }
}
```

### 5.2 Secret response

If allowed, return secret only to the requesting process.

**Future improvements:**

- Return short-lived derived token instead of raw secret
- Inject secret only into child process environment
- Redact secret in logs
- Prevent reading secret into agent context where possible
