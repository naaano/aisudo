use anyhow::Result;
use std::io::{self, Write};

use crate::config::{self, Config};

pub fn run() -> Result<()> {
    println!("aisudo — first-run setup\n");

    // Create directory structure
    config::create_dirs()?;
    println!("✓ Created ~/.aisudo/ directory structure");

    // Check if config already exists
    let existing = config::load_config()?;
    if existing.telegram_bot_token.is_some() {
        println!("\nConfiguration already exists.");
        print!("Overwrite? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Keeping existing configuration.");
            return Ok(());
        }
    }

    // Prompt for Telegram configuration
    println!("\n--- Telegram Transport Setup ---\n");
    println!("aisudo uses a Telegram bot to send approval notifications.");
    println!("You'll need to:");
    println!("  1. Open @BotFather on Telegram");
    println!("  2. Send /newbot and follow the prompts");
    println!("  3. Copy the bot token\n");

    print!("Enter your Telegram bot token: ");
    io::stdout().flush()?;
    let mut bot_token = String::new();
    io::stdin().read_line(&mut bot_token)?;
    let bot_token = bot_token.trim().to_string();

    if bot_token.is_empty() {
        println!("\nNo bot token provided. You can configure it later in ~/.aisudo/config.toml");
        let config = Config::default();
        config::save_config(&config)?;
        println!("✓ Wrote default config");
    } else {
        // Validate the bot token first
        print!("\nValidating bot token... ");
        io::stdout().flush()?;
        let bot_username = match validate_bot_token(&bot_token) {
            Ok(username) => {
                println!("✓");
                username
            }
            Err(e) => {
                println!("✗");
                anyhow::bail!("Invalid bot token: {}. Check the token and try again.", e);
            }
        };

        // Auto-detect chat ID by polling for messages
        println!("\nTo find your chat ID, send a message to your bot now.");
        println!("  → Open Telegram and message @{}", bot_username);
        println!("  → Send anything (e.g. /start)");
        println!("\nWaiting for a message...");

        let chat_id = match poll_for_chat_id(&bot_token) {
            Ok(id) => {
                println!("✓ Found chat ID: {}", id);
                id
            }
            Err(e) => {
                println!("\n⚠ Could not detect chat ID automatically: {}", e);
                println!("You can enter it manually. Visit:");
                println!("  https://api.telegram.org/bot{}/getUpdates", bot_token);
                println!("Look for 'chat' → 'id' in the first message.\n");

                print!("Enter your Telegram chat ID: ");
                io::stdout().flush()?;
                let mut manual_id = String::new();
                io::stdin().read_line(&mut manual_id)?;
                let manual_id = manual_id.trim().to_string();
                if manual_id.is_empty() {
                    anyhow::bail!("No chat ID provided. Run aisudo init again when ready.");
                }
                manual_id
            }
        };

        let config = Config {
            telegram_bot_token: Some(bot_token.clone()),
            telegram_chat_id: Some(chat_id),
            ..Config::default()
        };

        config::save_config(&config)?;
        println!("\n✓ Configuration saved to ~/.aisudo/config.toml");

        // Test connectivity
        println!("\nTesting Telegram connectivity...");
        match test_telegram(&config) {
            Ok(_) => println!("✓ Telegram test message sent successfully!"),
            Err(e) => println!("⚠ Could not send test message: {}", e),
        }
    }

    // Write default policy
    let default_policy = include_str!("../../default-policy.toml");
    let policy_path = config::policy_path()?;
    if !policy_path.exists() {
        std::fs::write(&policy_path, default_policy)?;
        println!("✓ Wrote default policy to ~/.aisudo/private/policy.toml");
    } else {
        println!("  Policy file already exists, skipping");
    }

    println!("\n✓ aisudo setup complete!");
    println!("\nNext steps:");
    println!("  1. Start the daemon:    aisudo daemon");
    println!("  2. Pair your phone:     aisudo pair");
    println!("  3. Gate a command:      aisudo exec -- pnpm install");

    Ok(())
}

fn validate_bot_token(token: &str) -> Result<String> {
    let url = format!("https://api.telegram.org/bot{}/getMe", token);
    let client = reqwest::blocking::Client::new();
    let resp = client.get(&url).send()?;

    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }

    let body: serde_json::Value = resp.json()?;
    if body["ok"].as_bool() != Some(true) {
        anyhow::bail!("{}", body["description"].as_str().unwrap_or("unknown error"));
    }

    let username = body["result"]["username"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    Ok(username)
}

fn poll_for_chat_id(token: &str) -> Result<String> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.telegram.org/bot{}/getUpdates", token);

    // First, clear any stale updates by consuming them with a high offset
    let clear_resp = client
        .get(&url)
        .query(&[("offset", "-1")])
        .send()?;
    if let Ok(body) = clear_resp.json::<serde_json::Value>() {
        if let Some(updates) = body["result"].as_array() {
            if let Some(last) = updates.last() {
                let skip_offset = last["update_id"].as_i64().unwrap_or(0) + 1;
                let _ = client
                    .get(&url)
                    .query(&[("offset", skip_offset.to_string())])
                    .send();
            }
        }
    }

    // Now poll for fresh updates
    let timeout = std::time::Duration::from_secs(60);
    let start = std::time::Instant::now();
    let mut dots = 0;

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("timed out after 60 seconds");
        }

        let resp = client
            .get(&url)
            .query(&[("timeout", "5")])
            .send()?;

        let body: serde_json::Value = resp.json()?;

        if let Some(updates) = body["result"].as_array() {
            for update in updates {
                if let Some(message) = update.get("message") {
                    if let Some(chat) = message.get("chat") {
                        if let Some(chat_id) = chat["id"].as_i64() {
                            return Ok(chat_id.to_string());
                        }
                    }
                }
            }
        }

        dots = (dots + 1) % 4;
        let indicator = ".".repeat(dots + 1);
        print!("\r  Waiting for message{}  ", indicator);
        io::stdout().flush()?;
    }
}

fn test_telegram(config: &Config) -> Result<()> {
    let token = config.telegram_bot_token.as_ref().unwrap();
    let chat_id = config.telegram_chat_id.as_ref().unwrap();

    let url = format!("https://api.telegram.org/bot{}/sendMessage", token);

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "text": "🤖 aisudo connected! You will receive approval notifications here.",
            "parse_mode": "HTML"
        }))
        .send()?;

    if !resp.status().is_success() {
        anyhow::bail!("Telegram API returned status {}", resp.status());
    }

    Ok(())
}
