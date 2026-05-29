# Secret broker, not full gate

aisudo protects secrets and catches risky actions. It does not gate every command.

The original spec positioned aisudo as "sudo for AI agents" — approve every shell command, every file access, every network call. This would repeat the macOS TCC mistake: constant approval prompts that users learn to reflexively dismiss. Every coding agent already offers a "full access" mode and most users enable it immediately.

We chose to invert the model: **default allow, targeted protection**. The daemon brokers access to secrets (credentials, tokens, API keys) and escalates actions classified as high-risk (deploy, publish, destructive ops). Everything else flows through without interruption.

This means aisudo's value is in the sensitive layer — Keychain integration, token scoping, risk heuristics for package managers and destructive commands — not in being a universal command gate.
