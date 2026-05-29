use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, oneshot};

use crate::audit::{self, AuditEntry};
use crate::config::{self, Config};
use crate::crypto::{DeviceRegistry, NonceStore};
use crate::grants::{self, Grant};
use crate::policy::{self, Evaluation, Policy};
use crate::protocol::{Action, Decision, GrantMode, Request, Response};
use crate::transport::{TelegramTransport, CallbackAction};

// ─── Daemon State ───────────────────────────────────────────────────

/// Shared state for the daemon
pub struct DaemonState {
    pub config: Config,
    pub policy: Policy,
    pub devices: DeviceRegistry,
    pub grants: Vec<Grant>,
    pub nonce_store: NonceStore,
    pub pending_requests: HashMap<String, PendingRequest>,
    pub telegram: Option<TelegramTransport>,
}

/// A pending request waiting for approval
pub struct PendingRequest {
    pub request: Request,
    pub evaluation: Evaluation,
    pub response_tx: oneshot::Sender<Response>,
    pub created_at: OffsetDateTime,
}

impl DaemonState {
    pub fn new() -> Result<Self> {
        let config = config::load_config().unwrap_or_default();
        let policy_path = config::policy_path()?;
        let policy = if policy_path.exists() {
            policy::load_policy(&policy_path)?
        } else {
            // Use default policy
            let default_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("default-policy.toml");
            policy::load_policy(&default_path)?
        };

        let devices_path = config::devices_path()?;
        let devices = DeviceRegistry::load(&devices_path).unwrap_or_default();

        let grants_path = config::grants_path()?;
        let grants_list = grants::load_grants(&grants_path).unwrap_or_default();

        let telegram = if let (Some(token), Some(chat_id)) = (&config.telegram_bot_token, &config.telegram_chat_id) {
            Some(TelegramTransport::new(token.clone(), chat_id.clone()))
        } else {
            None
        };

        Ok(Self {
            config,
            policy,
            devices,
            grants: grants_list,
            nonce_store: NonceStore::new(),
            pending_requests: HashMap::new(),
            telegram,
        })
    }

    /// Process a request and return a response
    pub async fn process_request(&mut self, request: Request) -> Result<Response> {
        // Validate request
        if request.expires_at < OffsetDateTime::now_utc() {
            return Ok(Response::Denied {
                reason: "Request expired".to_string(),
            });
        }

        // Check nonce
        if !self.nonce_store.check_and_use(&request.nonce) {
            return Ok(Response::Denied {
                reason: "Nonce already used (replay detected)".to_string(),
            });
        }

        // Evaluate against policy
        let evaluation = policy::evaluate(&self.policy, &request.action, &request.app.name);

        match evaluation.decision {
            Decision::Allow => {
                // Log and allow
                self.log_request(&request, &evaluation, true).await?;

                // Create a grant if requested
                if let Some(ref grant_mode) = request.requested_grant {
                    let grant = match grant_mode {
                        GrantMode::Once => {
                            Grant::new_once(&request.app.name, &request.action, None)
                        }
                        GrantMode::ForDuration { duration_secs } => {
                            Grant::new_for_duration(
                                &request.app.name,
                                &request.action,
                                *duration_secs as i64,
                                None,
                            )
                        }
                        _ => Grant::new_once(&request.app.name, &request.action, None),
                    };
                    self.grants.push(grant.clone());
                    self.save_grants()?;

                    return Ok(Response::Allowed {
                        grant_id: Some(grant.id),
                        message: "Allowed by policy".to_string(),
                    });
                }

                Ok(Response::Allowed {
                    grant_id: None,
                    message: "Allowed by policy".to_string(),
                })
            }
            Decision::Alert => {
                // Log, notify silently, allow
                self.log_request(&request, &evaluation, true).await?;
                Ok(Response::Allowed {
                    grant_id: None,
                    message: "Allowed (alert sent)".to_string(),
                })
            }
            Decision::Ask => {
                // Log escalation
                self.log_request(&request, &evaluation, false).await?;

                // Return escalated status
                Ok(Response::Escalated {
                    request_id: request.request_id.clone(),
                    message: "Human approval required".to_string(),
                })
            }
            Decision::Deny => {
                self.log_request(&request, &evaluation, false).await?;
                Ok(Response::Denied {
                    reason: format!("Denied by rule: {}", evaluation.matched_rule),
                })
            }
        }
    }

    /// Log a request to the audit log
    async fn log_request(&self, request: &Request, evaluation: &Evaluation, _executed: bool) -> Result<()> {
        let entry = AuditEntry::new(
            request.request_id.clone(),
            request.app.name.clone(),
            request.action.kind_str().to_string(),
            request.action.summary(),
            evaluation.decision,
            evaluation.risk.to_string(),
            evaluation.severity,
            evaluation.matched_rule.clone(),
            evaluation.reasons.clone(),
        );

        let log_path = config::audit_path()?;
        audit::append(&log_path, &entry)?;

        Ok(())
    }

    /// Save grants to disk
    fn save_grants(&self) -> Result<()> {
        let path = config::grants_path()?;
        grants::save_grants(&path, &self.grants)
    }

    /// Create an approval request for transport
    pub fn create_approval_request(&self, request: &Request, evaluation: &Evaluation) -> crate::protocol::ApprovalRequest {
        crate::protocol::ApprovalRequest {
            request_id: request.request_id.clone(),
            created_at: request.created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            expires_at: request.expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            app_name: request.app.name.clone(),
            action_summary: request.action.summary(),
            action_kind: request.action.kind_str().to_string(),
            risk: evaluation.risk,
            risk_reasons: evaluation.reasons.clone(),
            recommendation: evaluation.decision,
            nonce: request.nonce.clone(),
            request_hash: request.request_hash.clone(),
        }
    }
}

// ─── Socket Handler ─────────────────────────────────────────────────

/// Handle a single socket connection
async fn handle_connection(
    stream: UnixStream,
    state: Arc<Mutex<DaemonState>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Read the request
    buf_reader.read_line(&mut line).await?;

    let request: Request = serde_json::from_str(&line)
        .context("Failed to parse request JSON")?;

    // Process the request
    let response = {
        let mut state = state.lock().await;
        state.process_request(request.clone()).await?
    };

    // If escalated, send notification and wait for approval
    let final_response = if let Response::Escalated { .. } = &response {
        let state_guard = state.lock().await;
        let telegram = state_guard.telegram.clone();
        drop(state_guard);

        if let Some(telegram) = telegram {
            let state_guard = state.lock().await;
            let approval_req = state_guard.create_approval_request(
                &request,
                &state_guard.policy.evaluate_for_display(&request.action, &request.app.name),
            );
            drop(state_guard);

            // Send notification
            telegram.notify(&approval_req).await?;

            // Create channel for response
            let (tx, rx) = oneshot::channel();

            // Store pending request
            {
                let mut state = state.lock().await;
                let evaluation = policy::evaluate(&state.policy, &request.action, &request.app.name);
                state.pending_requests.insert(
                    request.request_id.clone(),
                    PendingRequest {
                        request: request.clone(),
                        evaluation,
                        response_tx: tx,
                        created_at: OffsetDateTime::now_utc(),
                    },
                );
            }

            // Wait for approval (with timeout)
            let timeout = tokio::time::Duration::from_secs(300);
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(approval_response)) => approval_response,
                _ => {
                    // Timeout or error
                    let mut state = state.lock().await;
                    state.pending_requests.remove(&request.request_id);

                    Response::Denied {
                        reason: "Request timed out waiting for approval".to_string(),
                    }
                }
            }
        } else {
            // No transport configured - use TUI fallback
            response
        }
    } else {
        response
    };

    // Send response
    let response_json = serde_json::to_string(&final_response)?;
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    Ok(())
}

// ─── Telegram Polling ───────────────────────────────────────────────

/// Background task to poll Telegram for callback updates
async fn telegram_poll_loop(state: Arc<Mutex<DaemonState>>) {
    loop {
        let updates = {
            let state = state.lock().await;
            if let Some(ref telegram) = state.telegram {
                telegram.poll_updates().await.unwrap_or_default()
            } else {
                Vec::new()
            }
        };

        for update in updates {
            if let Some((request_id, action)) = update.parse_decision() {
                let mut state = state.lock().await;

                if let Some(pending) = state.pending_requests.remove(&request_id) {
                    let response = match action {
                        CallbackAction::Deny => Response::Denied {
                            reason: "Denied by human".to_string(),
                        },
                        CallbackAction::ApproveOnce => {
                            // Create a grant
                            let grant = Grant::new_once(
                                &pending.request.app.name,
                                &pending.request.action,
                                None,
                            );
                            state.grants.push(grant.clone());
                            let _ = state.save_grants();

                            Response::Allowed {
                                grant_id: Some(grant.id),
                                message: "Approved by human (once)".to_string(),
                            }
                        }
                        CallbackAction::ApproveForDuration { duration_secs } => {
                            let grant = Grant::new_for_duration(
                                &pending.request.app.name,
                                &pending.request.action,
                                duration_secs as i64,
                                None,
                            );
                            state.grants.push(grant.clone());
                            let _ = state.save_grants();

                            Response::Allowed {
                                grant_id: Some(grant.id),
                                message: format!("Approved by human ({} min)", duration_secs / 60),
                            }
                        }
                        CallbackAction::ApproveAlways => {
                            Response::Allowed {
                                grant_id: None,
                                message: "Approved by human (always)".to_string(),
                            }
                        }
                    };

                    let _ = pending.response_tx.send(response.clone());

                    // Update the Telegram message
                    if let Some(ref telegram) = state.telegram {
                        let status_text = match &response {
                            Response::Allowed { .. } => "✅ Approved",
                            Response::Denied { .. } => "❌ Denied",
                            _ => "⏳ Processing",
                        };
                        let _ = telegram.edit_message(
                            update.message_id,
                            &format!("{} — {}", status_text, request_id),
                        ).await;
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    }
}

// ─── Main Daemon Entry ──────────────────────────────────────────────

/// Run the daemon
pub async fn run() -> Result<()> {
    // Initialize state
    let state = Arc::new(Mutex::new(DaemonState::new()?));

    // Get socket path
    let socket_path = config::socket_path()?;

    // Remove old socket if it exists
    if socket_path.exists() {
        tokio::fs::remove_file(&socket_path).await?;
    }

    // Create socket listener
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind socket at {}", socket_path.display()))?;

    // Set socket permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).await?;
    }

    tracing::info!("aisudo daemon listening on {}", socket_path.display());

    // Start Telegram polling if configured
    let state_clone = state.clone();
    tokio::spawn(async move {
        telegram_poll_loop(state_clone).await;
    });

    // Accept connections
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                tracing::error!("Connection error: {}", e);
            }
        });
    }
}

impl Policy {
    /// Evaluate a request for display purposes (returns evaluation without side effects)
    pub fn evaluate_for_display(&self, action: &Action, app_name: &str) -> Evaluation {
        policy::evaluate(self, action, app_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::protocol::App;

    fn test_state() -> DaemonState {
        let config = Config::default();
        let policy_str = r#"
[defaults]
unknown = "allow"
unknown_secrets = "ask"

[[rules]]
name = "ask npm install"
action = "exec"
argv = ["npm", "install", "*"]
decision = "ask"
risk = "high"

[[rules]]
name = "allow git status"
action = "exec"
argv = ["git", "status"]
decision = "allow"
risk = "low"
"#;
        let policy: Policy = toml::from_str(policy_str).unwrap();

        DaemonState {
            config,
            policy,
            devices: DeviceRegistry::default(),
            grants: Vec::new(),
            nonce_store: NonceStore::new(),
            pending_requests: HashMap::new(),
            telegram: None,
        }
    }

    #[tokio::test]
    async fn test_process_allow() {
        // Ensure dirs exist
        let _ = config::create_dirs();
        
        let mut state = test_state();
        let request = Request::new(
            App {
                name: "test".to_string(),
                pid: 123,
                cwd: PathBuf::from("/tmp"),
            },
            Action::Exec {
                argv: vec!["git".to_string(), "status".to_string()],
                cwd: PathBuf::from("/tmp"),
                env_requested: vec![],
            },
            None,
            None,
        );

        let response = state.process_request(request).await.unwrap();
        assert!(matches!(response, Response::Allowed { .. }));
    }

    #[tokio::test]
    async fn test_process_ask() {
        let _ = config::create_dirs();
        
        let mut state = test_state();
        let request = Request::new(
            App {
                name: "test".to_string(),
                pid: 123,
                cwd: PathBuf::from("/tmp"),
            },
            Action::Exec {
                argv: vec!["npm".to_string(), "install".to_string(), "express".to_string()],
                cwd: PathBuf::from("/tmp"),
                env_requested: vec![],
            },
            None,
            None,
        );

        let response = state.process_request(request).await.unwrap();
        assert!(matches!(response, Response::Escalated { .. }));
    }

    #[tokio::test]
    async fn test_replay_detection() {
        let _ = config::create_dirs();
        
        let mut state = test_state();
        let request = Request::new(
            App {
                name: "test".to_string(),
                pid: 123,
                cwd: PathBuf::from("/tmp"),
            },
            Action::Exec {
                argv: vec!["git".to_string(), "status".to_string()],
                cwd: PathBuf::from("/tmp"),
                env_requested: vec![],
            },
            None,
            None,
        );

        let nonce = request.nonce.clone();

        // First request should succeed
        let response = state.process_request(request.clone()).await.unwrap();
        assert!(matches!(response, Response::Allowed { .. }));

        // Replay should be denied
        let mut replay = request.clone();
        replay.request_id = "req_replay".to_string();
        replay.nonce = nonce;

        let response = state.process_request(replay).await.unwrap();
        assert!(matches!(response, Response::Denied { .. }));
    }

    #[tokio::test]
    async fn test_expired_request() {
        let _ = config::create_dirs();
        
        let mut state = test_state();
        let mut request = Request::new(
            App {
                name: "test".to_string(),
                pid: 123,
                cwd: PathBuf::from("/tmp"),
            },
            Action::Exec {
                argv: vec!["git".to_string(), "status".to_string()],
                cwd: PathBuf::from("/tmp"),
                env_requested: vec![],
            },
            None,
            None,
        );

        // Set expiry to the past
        request.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);

        let response = state.process_request(request).await.unwrap();
        assert!(matches!(response, Response::Denied { .. }));
    }
}
