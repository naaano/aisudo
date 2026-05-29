# User-owned Telegram bot, no shared infrastructure

Each user creates their own Telegram bot via BotFather. aisudo runs the bot locally via the daemon. No shared aisudo cloud service, no routing infrastructure, no trust dependency.

The bot token is stored in `~/.aisudo/config` or as an environment variable — never pasted into a conversation. The agent reads it from the file/env. This is deliberate: aisudo practices what it preaches. If the product is about protecting secrets, the setup flow must model good security hygiene.

The agent walks the user through BotFather (3 messages), instructs them to save the token to `~/.aisudo/telegram.token`, and reads it from there. Token never appears in conversation context or history.
