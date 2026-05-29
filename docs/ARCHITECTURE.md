# Architecture

## Main Components

```
+---------------------+
| Agent / Tool / IDE  |
| Claude Code, Cursor |
| Kilo, Pi, Hermes    |
+----------+----------+
           |
           | CLI / local socket / JSON
           v
+---------------------+
| aisudo daemon       |
| Rust                |
|                     |
| - policy engine     |
| - request queue     |
| - grant engine      |
| - device registry   |
| - audit log         |
| - secret gate       |
| - transport manager |
+----------+----------+
           |
           | notify
           v
+---------------------+
| Phone / PWA / ntfy  |
| trusted device      |
+----------+----------+
           |
           | signed decision
           v
+---------------------+
| aisudo daemon       |
| verifies signature  |
| applies decision    |
+---------------------+
```

---

## Configuration Storage

### Suggested layout

```
~/.aisudo/
  aisudo.sock
  public/
    audit.log
    requests/
  private/
    config.enc
    devices.enc
    policy.enc
    grants.enc
    secrets.enc
```

### Permissions

```
~/.aisudo/private: 0700
~/.aisudo/aisudo.sock: user-only
```

### Important caveat

If the agent runs as the same OS user, filesystem permissions alone are **not** a strong boundary.

The daemon must validate:

- Caller identity where possible
- Request details
- Policy
- Active grants
- Human approvals

Encryption at rest helps, but daemon-side authorization is the main control.

---

## Secret Storage

Use platform storage where possible:

| Platform | Storage |
|---|---|
| macOS | Keychain |
| Windows | DPAPI / Credential Manager |
| Linux | Secret Service (when available) |
| Fallback | Encrypted file (via `age` crate) |

---

## Single Binary Modes

The single Rust binary operates in multiple modes:

```bash
aisudo daemon          # long-running background service
aisudo exec -- ...     # authorize-and-execute
aisudo request --json  # pure authorization request
aisudo pair            # device pairing
aisudo policy ...      # policy management
aisudo audit ...       # audit log queries
aisudo config ...      # configuration
```

No Phoenix app, no Python daemon, no TypeScript backend.
