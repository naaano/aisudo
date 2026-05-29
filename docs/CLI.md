# CLI Interface & UX Examples

## 1. CLI Commands

### 1.1 Basic commands

```bash
aisudo init
aisudo daemon
aisudo status
aisudo pair
aisudo devices list
aisudo devices revoke DEVICE_ID
aisudo exec -- pnpm install
aisudo ask secret GITHUB_TOKEN
aisudo request --json < request.json
aisudo requests pending
aisudo request show REQ_ID
aisudo grants list
aisudo grants revoke GRANT_ID
aisudo audit tail
aisudo audit show REQ_ID
aisudo policy propose ./policy.toml
aisudo policy diff PROPOSAL_ID
aisudo policy apply PROPOSAL_ID
aisudo policy explain REQ_ID
```

### 1.2 Agent-safe commands

These should be safe for agents to call without human confirmation:

```bash
aisudo can exec -- pnpm install
aisudo request --json < request.json
aisudo request show REQ_ID
aisudo audit mine --app claude-code
```

### 1.3 Human-only commands

These require TUI confirmation, local user confirmation, or trusted-device approval:

```bash
aisudo policy cat
aisudo policy apply PROPOSAL_ID
aisudo devices list
aisudo devices revoke DEVICE_ID
aisudo grants list --all
aisudo audit all
aisudo config export
```

---

## 2. UX Examples

### 2.1 CLI request — approval flow

```bash
$ aisudo exec -- pnpm install
```

**Output while waiting:**

```
aisudo: human approval required

Request: req_01j...
Action: pnpm install
Risk: high
Reason:
  - package manager execution
  - may execute lifecycle scripts
  - network access likely

Waiting for approval...
```

**Phone notification:**

```
aisudo approval needed

claude-code wants to run:
pnpm install

Risk: high
Tap to review.
```

**Phone approval options:**

```
Deny
Approve once
Approve for 10 minutes in this repo
Always allow this exact command in this repo
```

**CLI after approval:**

```
Approved by Hernan iPhone.
Running command...
```

### 2.2 Policy proposal — full flow

**Agent creates proposal:**

```bash
$ aisudo policy propose .aisudo/policy.proposed.toml
```

**Human reviews:**

```bash
$ aisudo policy diff proposal_01j...
```

**Output:**

```diff
+ [[rules]]
+ name = "allow mix test for my_app"
+ app = "claude-code"
+ action = "exec"
+ argv = ["mix", "test", "*"]
+ cwd = "/Users/hernan/dev/my_app"
+ decision = "allow"
+ risk = "low"
```

**Human applies:**

```bash
$ aisudo policy apply proposal_01j...
```

_(Requires human approval.)_
