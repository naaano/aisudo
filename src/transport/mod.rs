use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::protocol::{ApprovalRequest, Decision, RiskLevel};

// ─── Telegram Bot Client ────────────────────────────────────────────

/// Telegram Bot API client
#[derive(Clone)]
pub struct TelegramTransport {
    bot_token: String,
    chat_id: String,
    client: reqwest::Client,
    offset: Arc<Mutex<i64>>,
}

impl TelegramTransport {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: reqwest::Client::new(),
            offset: Arc::new(Mutex::new(0)),
        }
    }

    /// Send an approval request notification
    pub async fn notify(&self, request: &ApprovalRequest) -> Result<()> {
        let message = format_approval_message(request);
        let keyboard = create_inline_keyboard(request);

        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML",
                "reply_markup": keyboard,
            }))
            .send()
            .await
            .context("Failed to send Telegram message")?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Telegram API error: {}", body);
        }

        Ok(())
    }

    /// Poll for callback queries (button taps)
    pub async fn poll_updates(&self) -> Result<Vec<CallbackUpdate>> {
        let url = format!("https://api.telegram.org/bot{}/getUpdates", self.bot_token);

        let offset = *self.offset.lock().await;

        let response = self.client
            .get(&url)
            .query(&serde_json::json!({
                "offset": offset + 1,
                "timeout": 1,
                "allowed_updates": ["callback_query"],
            }).to_string())
            .send()
            .await
            .context("Failed to poll Telegram updates")?;

        let body: serde_json::Value = response.json().await
            .context("Failed to parse Telegram response")?;

        let mut updates = Vec::new();

        if let Some(result) = body["result"].as_array() {
            for update in result {
                if let Some(callback) = update.get("callback_query") {
                    let callback_data = callback["data"].as_str().unwrap_or("").to_string();
                    let message_id = callback["message"]["message_id"].as_i64().unwrap_or(0);
                    let update_id = update["update_id"].as_i64().unwrap_or(0);

                    updates.push(CallbackUpdate {
                        callback_data,
                        message_id,
                        update_id,
                    });

                    // Update offset
                    *self.offset.lock().await = update_id;
                }
            }
        }

        Ok(updates)
    }

    /// Answer a callback query (dismiss the loading spinner)
    pub async fn answer_callback(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/answerCallbackQuery", self.bot_token);

        self.client
            .post(&url)
            .json(&serde_json::json!({
                "callback_query_id": callback_query_id,
                "text": text,
            }))
            .send()
            .await
            .context("Failed to answer callback query")?;

        Ok(())
    }

    /// Edit a message (e.g., to show the result after approval)
    pub async fn edit_message(&self, message_id: i64, text: &str) -> Result<()> {
        let url = format!("https://api.telegram.org/bot{}/editMessageText", self.bot_token);

        self.client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": self.chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "HTML",
            }))
            .send()
            .await
            .context("Failed to edit message")?;

        Ok(())
    }
}

// ─── Callback Update ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CallbackUpdate {
    /// The callback data (e.g., "approve_once:req_123")
    pub callback_data: String,

    /// The message ID this callback belongs to
    pub message_id: i64,

    /// The update ID
    pub update_id: i64,
}

impl CallbackUpdate {
    /// Parse the callback data into a decision
    pub fn parse_decision(&self) -> Option<(String, CallbackAction)> {
        let parts: Vec<&str> = self.callback_data.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }

        let action = match parts[0] {
            "deny" => CallbackAction::Deny,
            "approve_once" => CallbackAction::ApproveOnce,
            "approve_10min" => CallbackAction::ApproveForDuration { duration_secs: 600 },
            "approve_always" => CallbackAction::ApproveAlways,
            _ => return None,
        };

        Some((parts[1].to_string(), action))
    }
}

#[derive(Debug, Clone)]
pub enum CallbackAction {
    Deny,
    ApproveOnce,
    ApproveForDuration { duration_secs: u64 },
    ApproveAlways,
}

// ─── Message Formatting ─────────────────────────────────────────────

/// Format an approval request as a Telegram message
pub fn format_approval_message(request: &ApprovalRequest) -> String {
    let risk_emoji = match request.risk {
        RiskLevel::Low => "🟢",
        RiskLevel::Medium => "🟡",
        RiskLevel::High => "🟠",
        RiskLevel::Critical => "🔴",
    };

    let mut msg = format!(
        "🤖 <b>aisudo approval needed</b>\n\n\
         <b>App:</b> {}\n\
         <b>Action:</b> {}\n\
         {} <b>Risk:</b> {}\n",
        escape_html(&request.app_name),
        escape_html(&request.action_summary),
        risk_emoji,
        request.risk
    );

    if !request.risk_reasons.is_empty() {
        msg.push_str("\n<b>Reasons:</b>\n");
        for reason in &request.risk_reasons {
            msg.push_str(&format!("• {}\n", escape_html(reason)));
        }
    }

    if let Some(recommendation) = request_recommendation(request) {
        msg.push_str(&format!("\n💡 <b>Recommendation:</b> {}\n", recommendation));
    }

    msg
}

/// Create an inline keyboard for the approval message
fn create_inline_keyboard(request: &ApprovalRequest) -> serde_json::Value {
    let request_id = &request.request_id;

    serde_json::json!({
        "inline_keyboard": [
            [
                {"text": "❌ Deny", "callback_data": format!("deny:{}", request_id)},
                {"text": "✅ Once", "callback_data": format!("approve_once:{}", request_id)},
                {"text": "⏰ 10 min", "callback_data": format!("approve_10min:{}", request_id)},
                {"text": "♾️ Always", "callback_data": format!("approve_always:{}", request_id)},
            ]
        ]
    })
}

fn request_recommendation(request: &ApprovalRequest) -> Option<&'static str> {
    match (&request.risk, &request.recommendation) {
        (RiskLevel::Critical, Decision::Ask) => Some("high risk, require explicit approval"),
        (RiskLevel::High, Decision::Ask) => Some("elevated risk, review carefully"),
        _ => None,
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> ApprovalRequest {
        ApprovalRequest {
            request_id: "req_test123".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-01-01T00:05:00Z".to_string(),
            app_name: "claude-code".to_string(),
            action_summary: "pnpm install express".to_string(),
            action_kind: "exec".to_string(),
            risk: RiskLevel::High,
            risk_reasons: vec![
                "package manager execution".to_string(),
                "may execute lifecycle scripts".to_string(),
            ],
            recommendation: Decision::Ask,
            nonce: "abc123".to_string(),
            request_hash: "sha256:def456".to_string(),
        }
    }

    #[test]
    fn test_format_approval_message() {
        let request = test_request();
        let msg = format_approval_message(&request);

        assert!(msg.contains("aisudo approval needed"));
        assert!(msg.contains("claude-code"));
        assert!(msg.contains("pnpm install express"));
        assert!(msg.contains("Risk:") || msg.contains("risk:"), "Expected risk level in message");
        assert!(msg.contains("package manager execution"));
    }

    #[test]
    fn test_create_inline_keyboard() {
        let request = test_request();
        let keyboard = create_inline_keyboard(&request);

        // Should have 4 buttons
        let buttons = keyboard["inline_keyboard"][0].as_array().unwrap();
        assert_eq!(buttons.len(), 4);

        // Check callback data format
        assert_eq!(buttons[0]["callback_data"].as_str().unwrap(), "deny:req_test123");
        assert_eq!(buttons[1]["callback_data"].as_str().unwrap(), "approve_once:req_test123");
    }

    #[test]
    fn test_callback_parse() {
        let update = CallbackUpdate {
            callback_data: "approve_once:req_test123".to_string(),
            message_id: 1,
            update_id: 1,
        };

        let (req_id, action) = update.parse_decision().unwrap();
        assert_eq!(req_id, "req_test123");
        assert!(matches!(action, CallbackAction::ApproveOnce));
    }

    #[test]
    fn test_callback_parse_deny() {
        let update = CallbackUpdate {
            callback_data: "deny:req_test123".to_string(),
            message_id: 1,
            update_id: 1,
        };

        let (req_id, action) = update.parse_decision().unwrap();
        assert_eq!(req_id, "req_test123");
        assert!(matches!(action, CallbackAction::Deny));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<b>test</b>"), "&lt;b&gt;test&lt;/b&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }
}
