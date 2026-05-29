# Threat Model & Security Model

---

## 1. Threat Model

### 1.1 Threats in scope

`aisudo` should help against:

- Compromised npm/pip package
- Malicious package lifecycle scripts
- Prompt injection causing an agent to perform dangerous actions
- Agent attempting to read secrets
- Agent attempting to modify sensitive files (e.g., `~/.ssh/config`)
- Agent attempting to install tools globally
- Agent attempting to push code or publish packages
- Agent attempting to deploy to production
- Agent attempting to create long-lived grants
- Rogue automation trying to reuse previous approval
- Approval spoofing through public pub/sub channels
- Replaying old approvals

### 1.2 Threats partially in scope

`aisudo` can reduce blast radius but cannot fully solve:

- Malware already running as the same OS user
- Compromised terminal/IDE process
- Kernel-level compromise
- Hardware compromise
- Malicious human-approved policy
- Secrets already exposed before `aisudo` was installed
- Tools that bypass `aisudo`

### 1.3 Threats out of scope for MVP

- Full EDR
- OS-level mandatory access control
- Complete filesystem sandboxing
- Full network egress control
- Replacing macOS TCC / Windows UAC
- Browser session isolation

---

## 2. Security Model

### 2.1 Core rule

**Approval transport is not authorization.**

Example:

```
ntfy notification arrives on phone
```

This does **not** mean approval.

Actual approval requires a **signed decision** from a paired authorizer device.

### 2.2 Signed approvals

Every authorizer device has its own signing key. The daemon stores the device public key.

For each high-risk request, daemon creates:

- `request_id`
- canonical request body
- `request_hash`
- `nonce`
- expiration time

The phone signs:

```
decision | request_id | request_hash | nonce | expires_at
```

The daemon verifies:

1. Device is known
2. Signature is valid
3. Request hash matches
4. Request is not expired
5. Nonce was not reused
6. Device is allowed to approve this risk level
7. Policy still permits human override

### 2.3 Replay protection

A valid approval can only be used **once**.

Every request has:

- Unique `request_id`
- Random nonce
- Expiration
- Final state

#### Allowed request states

```
pending → approved | denied | expired | cancelled
approved → executed | failed
denied → (terminal)
expired → (terminal)
cancelled → (terminal)
executed → (terminal)
failed → (terminal)
```

A request cannot move backwards.

### 2.4 Grants are scoped

Avoid broad grants.

**Good:**
```
Allow claude-code to run `mix test` in this repo for 30 minutes.
```

**Bad:**
```
Allow claude-code to run all commands forever.
```
