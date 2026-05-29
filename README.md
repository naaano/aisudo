# aisudo

**Sudo for AI agents.** Policy-driven, human-approved, cryptographically verified authorization for autonomous AI tools.

---

## Tagline candidates

- `aisudo — sudo for AI agents`
- `aisudo — human approval for autonomous agents`
- `aisudo — policy gates for agentic tools`

## Branding direction

- Name sounds like `sudo` and lightly like `aikido`.
- Logo idea: martial arts belt + lock, circular aikido motion + shield, or terminal cursor inside a badge/crest.
- Avoid too much "police" aesthetic; prefer "defensive martial art" / "control without friction".

---

## The Problem

AI coding agents and remote automation agents can now:

- Run shell commands and install dependencies
- Access local files and read credentials
- Use browser sessions, email, Drive, GitHub, Slack, CI/CD, cloud APIs, etc.
- Operate while the human is away from the computer

This creates a major security problem:

> How do we preserve automation while preventing compromised packages, tools, prompts, or agents from using the developer machine as a worm launcher, credential exfiltration point, or production control surface?

Operating systems have some gates (macOS TCC, Windows UAC, browser permissions), but these are desktop-local and interrupt agentic workflows when the human isn't present.

**`aisudo` provides a separate authorization layer:**

> An AI tool can request permission. A human can approve, deny, or create a scoped grant from a trusted device. The decision is policy-driven, cryptographically verifiable, and logged.

---

## What is aisudo?

`aisudo` is a single Rust application that acts as a **local authorization broker** for AI agents and automation tools.

It is **not** a sandbox runtime, workflow engine, IDE, agent framework, or MCP-first tool.

It answers one question:

> **Is this app allowed to perform this action now?**

### Examples

```
claude-code wants to read GITHUB_TOKEN
Approve? deny / once / 15 min / always for this repo

kilo wants to run:
pnpm install @foo/bar
Approve? deny / once / always

cursor wants to modify:
~/.ssh/config
Recommendation: deny

pi wants to send email to client@example.com
Approve? deny / preview / allow drafts only

hermes wants to run:
terraform apply
Recommendation: high risk, require explicit approval
```

---

## Core Principles

1. **Single Rust binary** — one app, multiple modes (`daemon`, `exec`, `request`, `pair`, `policy`, `audit`).
2. **CLI and local socket first** — agents integrate via CLI, JSON over stdin/stdout, local Unix socket (macOS/Linux), or named pipe (Windows). MCP is optional later.
3. **Explicit integration first** — no magic interception in v1. Start with `aisudo exec -- pnpm install` and `aisudo ask secret GITHUB_TOKEN`.
4. **Authorization broker, not sandbox manager** — it gates access and records decisions. It does not create containers, manage worktrees, or replace agent tools.
5. **Agents may propose policy, never apply it** — agents can generate policy proposals for humans to review. Direct policy edits are forbidden.
6. **Policy is sensitive** — agents cannot read full policy. Only safe queries like `aisudo can exec -- pnpm install` are exposed.

---

## Non-Goals for MVP

- Native iOS/Android app, App Store/Google Play
- Cloud-hosted account system
- Full sandbox/container orchestration
- MCP as primary integration
- Browser extension, enterprise policy server
- SIEM integration, team workflows, two-person approval

See [`docs/MVP.md`](docs/MVP.md) for the full roadmap.

---

## Documentation

| Document | Description |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components, config storage, design constraints |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model and security model |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Device pairing, request/response model, grants, secrets |
| [`docs/POLICY.md`](docs/POLICY.md) | Policy format, proposals, risk levels |
| [`docs/TRANSPORTS.md`](docs/TRANSPORTS.md) | ntfy, local direct, transport trait |
| [`docs/CLI.md`](docs/CLI.md) | CLI commands and UX examples |
| [`docs/MVP.md`](docs/MVP.md) | Roadmap, open questions, Rust crate candidates |

---

## Design Summary

`aisudo` should be:

```
single-binary · Rust · CLI-first · local-socket-first
policy-driven · human-approved · device-paired · signature-verified
ntfy-compatible · PWA-friendly · audit-logged · agent-framework-agnostic
```

It should **not** be:

```
a full sandbox · a cloud service · an IDE · an agent framework
an MCP-first product · a workflow orchestrator · a native mobile app
```

> **`aisudo` is open-source, cryptographically approved, policy-driven sudo for AI agents.**

---

## License

TBD
