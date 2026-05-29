# Transports

## 1. Transport Layer

`aisudo` supports multiple approval transports. A transport notifies the human and receives signed decisions. **Transport does not provide authorization by itself.**

### 1.1 Transport trait

```rust
trait ApprovalTransport {
    fn notify(&self, request: ApprovalRequest) -> Result<()>;
    fn receive_decisions(&self) -> DecisionStream;
}
```

### 1.2 Initial transports (v1)

```
local-http
local-websocket
ntfy
tui
```

### 1.3 Future transports

```
tailscale
matrix
email
slack
desktop-notification
web-push
```

---

## 2. ntfy Integration

`ntfy` solves mobile notification and NAT traversal without requiring aisudo to ship a native mobile app.

### 2.1 Why ntfy helps

1. Phone notifications without building a mobile app.
2. Relay behavior when phone cannot reach the computer directly.
3. No inbound port required on the user's computer.
4. Cached messages if phone or daemon is briefly offline.
5. Existing Android/iOS/PWA clients.
6. Optional self-hosting.
7. Optional auth/ACL/tokens on private instances.

**Important security note:**

> ntfy is a wake-up and relay mechanism, **not** the trust boundary.

### 2.2 Public ntfy mode

Public `ntfy.sh` can be used for convenience if:

- Topics are high entropy
- Messages contain no secrets
- Full request details are not placed in notification body
- Signed approvals are mandatory
- Approvals expire quickly
- Replay protection is enforced

**Notification example:**

```json
{
  "topic": "aisudo-req-random-high-entropy-topic",
  "message": "Approval needed: pnpm install",
  "title": "aisudo approval",
  "priority": 4,
  "tags": ["warning", "lock"],
  "click": "https://aisudo.dev/app#/request/req_01j..."
}
```

### 2.3 Self-hosted ntfy mode

For stronger privacy, self-host ntfy.

Recommended server settings:

```yaml
auth-default-access: deny-all
```

Use:

- HTTPS
- Access tokens
- Per-device topics if possible
- ACLs
- Random high-entropy topics

### 2.4 ntfy approval flow

```
aisudo daemon
  -> publishes notification to request topic

phone/PWA
  -> receives notification
  -> loads request details
  -> signs decision
  -> publishes signed decision to response topic

aisudo daemon
  -> subscribes/polls response topic
  -> verifies signed decision
  -> applies decision
```

### 2.5 ntfy message contents

**Do not include secrets.**

**Safe notification body:**

```
Approval needed

App: claude-code
Action: pnpm install
Risk: high

Tap to review.
```

**Avoid:**

```
GITHUB_TOKEN=...
full env output
full file contents
secret paths if avoidable
customer data
```

---

## 3. Local Direct Transport

When phone and computer can communicate directly:

```
phone -> http://computer.local:3737
```

Or via Tailscale:

```
phone -> https://imac.tailnet-name.ts.net
```

Direct transport is lower latency and avoids public relay.

**Problems:**

- Volatile IP addresses
- mDNS may fail
- Phone may be outside LAN
- NAT/firewall issues
- TLS/local certificate complexity

**Strategy:** try direct transport first when available, fall back to ntfy relay.

---

## 4. Phone Approval Without Native Apps

### 4.1 PWA approach (preferred MVP)

A hosted or self-hosted PWA performs:

- Device pairing
- Key generation
- Request display
- Decision signing
- Sending signed decision back to daemon or relay

Private key storage:

- Browser WebCrypto key (non-exportable)
- IndexedDB for metadata
- Consider passcode/biometric gate later via WebAuthn

### 4.2 WebAuthn / passkeys (future)

**Pros:**

- Face ID / Touch ID / device unlock UX
- Phishing-resistant origin-bound authentication

**Cons:**

- Origin-bound, so local IP changes and `.local` names are awkward
- Better with stable HTTPS origin, Tailscale domain, or user-owned domain

MVP should **not** depend on WebAuthn.
