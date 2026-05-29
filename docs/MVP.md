# MVP Roadmap

## 1. Version Roadmap

### v0.1 — Foundation

- Single Rust binary
- Daemon mode
- CLI mode
- Local socket
- Request model
- Decision model
- Device pairing
- Signed approvals
- ntfy transport
- Local direct transport
- TUI fallback approval
- Encrypted config
- Policy engine
- Grants
- Audit log
- `exec` action
- `secret` action
- Policy proposal flow

### v0.2 — Polish

- PWA authorizer polish
- Better device management
- Policy diff UI in TUI
- Shell completions
- Wrappers for common tools
- Package-manager heuristics
- macOS launchd service
- Linux systemd user service
- Windows service support

### v0.3 — Extensions

- WebAuthn / passkey approval
- Tailscale-friendly direct transport
- Matrix transport
- GitHub/GitLab capability wrappers
- 1Password/op integration
- Team mode research

---

## 2. Non-Goals for MVP

- Native iOS/Android app, App Store/Google Play
- Phoenix dashboard
- Cloud-hosted account system
- MCP as primary integration path
- Full sandbox/container orchestration
- Automatic OS permission prompt forwarding
- Browser extension
- Enterprise policy server
- SIEM integration
- Team approval workflows
- Two-person approval rule

---

## 3. Rust Crate Candidates

| Crate | Purpose |
|---|---|
| `clap` | CLI parsing |
| `tokio` | Async runtime |
| `serde` | Serialization |
| `serde_json` | JSON protocol |
| `toml` | Policy/config parsing |
| `tracing` | Structured logging |
| `tracing-subscriber` | Log output |
| `time` | Timestamps |
| `uuid` or `ulid` | IDs |
| `ed25519-dalek` | Signatures |
| `rand` | Randomness |
| `sha2` | Hashing |
| `reqwest` | ntfy HTTP transport |
| `axum` | Local HTTP/PWA endpoint |
| `tungstenite` | WebSocket |
| `ratatui` | TUI |
| `crossterm` | Terminal backend |
| `directories` | Config paths |
| `keyring` | Platform credential store |
| `age` | Encrypted file fallback |

**Dependency policy should be strict** — this is security-sensitive software.

---

## 4. Open Questions

1. **Should MVP use Ed25519 device keys directly, or start with WebAuthn?**
   - Recommendation: Ed25519 via PWA WebCrypto first; WebAuthn later.

2. **Should public `ntfy.sh` be enabled by default?**
   - Recommendation: yes for convenience, but with strong warnings and no sensitive message bodies. Self-hosted or private relay should be recommended.

3. **How does daemon identify the calling app?**
   - PID/cwd/process name are spoofable by same-user attackers. Good enough for UX, not a strong security boundary. Stronger identity may require platform-specific signing checks later.

4. **Should `aisudo exec` actually execute commands, or only authorize?**
   - MVP should support `aisudo exec -- command` because it gives immediate usefulness. Also support pure authorization requests for tools that execute themselves.

5. **Should policy be encrypted by default?**
   - Recommendation: yes, but do not oversell it as protection against fully compromised same-user malware.

6. **Should logs be append-only?**
   - Recommendation: start with normal logs. Future: hash chain / tamper-evident audit log.

7. **How much request detail can be sent to phone?**
   - Recommendation: send summaries through ntfy; full details only through authenticated/signed PWA flow where possible.

---

## 5. Design Summary

`aisudo` **should be:**

```
single-binary · Rust · CLI-first · local-socket-first
policy-driven · human-approved · device-paired · signature-verified
ntfy-compatible · PWA-friendly · audit-logged · agent-framework-agnostic
```

`aisudo` should **not** be:

```
a full sandbox · a cloud service · an IDE · an agent framework
an MCP-first product · a workflow orchestrator · a native mobile app
```

> **`aisudo` is open-source, cryptographically approved, policy-driven sudo for AI agents.**
