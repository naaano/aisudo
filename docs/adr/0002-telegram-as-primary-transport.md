# Telegram as primary transport

aisudo uses Telegram Bot API as the primary notification and approval transport for v0.1.

Telegram is chosen over ntfy, PWA, and custom mobile apps because it requires zero install (everyone has it), supports inline keyboard buttons for one-tap approve/deny, has a trivial bot API, and needs no self-hosted infrastructure. The tradeoff — Telegram approvals aren't cryptographically signed — is acceptable for v0.1's threat model (rogue same-user agents, not nation-state adversaries). Signed approvals via PWA/WebCrypto can layer on later.

The guiding principle: WhatsApp stayed simple and won. ICQ died from complexity. Ship something that works today.
