use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;
use ulid::Ulid;

// ─── App ────────────────────────────────────────────────────────────

/// The process that directly calls aisudo via CLI or local socket.
/// Identity is self-reported (name, pid, cwd) and verifiable later via platform signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    /// Self-reported app name (e.g. "claude-code", "cursor", "pi")
    pub name: String,

    /// Process ID of the calling process
    pub pid: u32,

    /// Current working directory of the calling process
    pub cwd: PathBuf,
}

// ─── Action ─────────────────────────────────────────────────────────

/// A classified operation an App attempts.
/// Defined by a finite taxonomy; Apps provide the action kind plus structured metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Action {
    /// Execute a shell command
    Exec {
        /// Command and arguments
        argv: Vec<String>,
        /// Working directory for execution
        cwd: PathBuf,
        /// Environment variables requested (names only, not values)
        #[serde(default)]
        env_requested: Vec<String>,
    },

    /// Access a named secret
    Secret {
        /// Secret resource name (e.g. "GITHUB_TOKEN")
        resource: String,
        /// Purpose/reason for accessing the secret
        #[serde(default)]
        purpose: Option<String>,
    },

    /// Read a file
    FileRead {
        /// Path to the file
        path: PathBuf,
    },

    /// Write a file
    FileWrite {
        /// Path to the file
        path: PathBuf,
    },

    /// Network access
    Network {
        /// Target host/URL
        target: String,
        /// HTTP method if applicable
        #[serde(default)]
        method: Option<String>,
    },
}

impl Action {
    /// Human-readable summary of the action
    pub fn summary(&self) -> String {
        match self {
            Action::Exec { argv, .. } => argv.join(" "),
            Action::Secret { resource, .. } => format!("secret:{}", resource),
            Action::FileRead { path } => format!("read {}", path.display()),
            Action::FileWrite { path } => format!("write {}", path.display()),
            Action::Network { target, method } => {
                if let Some(m) = method {
                    format!("{} {}", m, target)
                } else {
                    format!("network:{}", target)
                }
            }
        }
    }

    /// The action kind as a string
    pub fn kind_str(&self) -> &'static str {
        match self {
            Action::Exec { .. } => "exec",
            Action::Secret { .. } => "secret",
            Action::FileRead { .. } => "file-read",
            Action::FileWrite { .. } => "file-write",
            Action::Network { .. } => "network",
        }
    }
}

// ─── Decision ───────────────────────────────────────────────────────

/// The outcome of a policy evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Run silently, log
    Allow,
    /// Run, send notification, log
    Alert,
    /// Block, send loud notification, wait for human approval
    Ask,
    /// Block silently, log
    Deny,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Alert => write!(f, "alert"),
            Decision::Ask => write!(f, "ask"),
            Decision::Deny => write!(f, "deny"),
        }
    }
}

// ─── Severity ───────────────────────────────────────────────────────

/// How urgently the human needs to respond
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No notification. Logged only.
    Info,
    /// Silent notification, review later.
    Alert,
    /// Loud notification, wake screen.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Alert => write!(f, "alert"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

// ─── Risk Level ─────────────────────────────────────────────────────

/// Risk classification for actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

// ─── Grant Mode ─────────────────────────────────────────────────────

/// Type of grant requested
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GrantMode {
    /// Approve this single action now
    Once,
    /// Approve for a duration
    ForDuration {
        /// Duration in seconds
        duration_secs: u64,
    },
    /// Approve for this workspace
    ForWorkspace {
        /// Workspace path
        workspace: PathBuf,
        /// Duration in seconds
        duration_secs: u64,
    },
    /// Approve this exact action forever (becomes a policy rule)
    ExactActionAlways,
}

// ─── Request ────────────────────────────────────────────────────────

/// A request for authorization from an app
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version
    pub version: u32,

    /// Unique request ID
    pub request_id: String,

    /// When the request was created
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// When the request expires
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,

    /// The requesting app
    pub app: App,

    /// The requested action
    pub action: Action,

    /// Human-readable reason for the request
    #[serde(default)]
    pub reason: Option<String>,

    /// Requested grant type
    #[serde(default)]
    pub requested_grant: Option<GrantMode>,

    /// Random nonce for replay protection
    pub nonce: String,

    /// SHA256 hash of the canonical request body
    pub request_hash: String,
}

impl Request {
    /// Create a new request with auto-generated ID and hash
    pub fn new(app: App, action: Action, reason: Option<String>, grant: Option<GrantMode>) -> Self {
        let now = OffsetDateTime::now_utc();
        let request_id = format!("req_{}", Ulid::new().to_string().to_lowercase());
        let nonce = generate_nonce();

        let mut req = Self {
            version: 1,
            request_id,
            created_at: now,
            expires_at: now + time::Duration::seconds(300), // 5 min default
            app,
            action,
            reason,
            requested_grant: grant,
            nonce,
            request_hash: String::new(),
        };

        req.request_hash = req.compute_hash();
        req
    }

    /// Compute SHA256 hash of the canonical request
    fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = format!(
            "{}|{}|{}|{}|{}",
            self.request_id,
            self.app.name,
            self.action.summary(),
            self.nonce,
            self.expires_at.unix_timestamp()
        );
        let hash = Sha256::digest(canonical.as_bytes());
        format!("sha256:{}", base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hash.as_slice()
        ))
    }
}

// ─── Response ───────────────────────────────────────────────────────

/// Immediate response from the daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Response {
    /// Human approval required
    Escalated {
        request_id: String,
        message: String,
    },

    /// Allowed by policy
    Allowed {
        grant_id: Option<String>,
        message: String,
    },

    /// Denied by policy
    Denied {
        reason: String,
    },
}

// ─── Approval Request (for transport) ───────────────────────────────

/// Request sent to a trusted device for approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub app_name: String,
    pub action_summary: String,
    pub action_kind: String,
    pub risk: RiskLevel,
    pub risk_reasons: Vec<String>,
    pub recommendation: Decision,
    pub nonce: String,
    pub request_hash: String,
}

// ─── Decision Message ───────────────────────────────────────────────

/// Signed decision from a trusted device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionMessage {
    pub request_id: String,
    pub decision: ApprovalDecision,
    pub device_id: String,
    pub request_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub signature: String,
}

/// The actual decision value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Deny,
    ApproveOnce,
    ApproveForDuration { duration_secs: u64 },
    ApproveForWorkspace { workspace: PathBuf, duration_secs: u64 },
    ApproveExactActionAlways,
    ApprovePolicyProposal,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app() -> App {
        App {
            name: "test-agent".to_string(),
            pid: 12345,
            cwd: PathBuf::from("/tmp/test"),
        }
    }

    #[test]
    fn test_action_summary() {
        let exec = Action::Exec {
            argv: vec!["pnpm".to_string(), "install".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };
        assert_eq!(exec.summary(), "pnpm install");
        assert_eq!(exec.kind_str(), "exec");

        let secret = Action::Secret {
            resource: "GITHUB_TOKEN".to_string(),
            purpose: None,
        };
        assert_eq!(secret.summary(), "secret:GITHUB_TOKEN");
        assert_eq!(secret.kind_str(), "secret");
    }

    #[test]
    fn test_request_creation() {
        let app = test_app();
        let action = Action::Exec {
            argv: vec!["git".to_string(), "status".to_string()],
            cwd: PathBuf::from("/tmp/test"),
            env_requested: vec![],
        };

        let req = Request::new(app, action, Some("checking status".to_string()), None);

        assert!(req.request_id.starts_with("req_"));
        assert!(req.request_hash.starts_with("sha256:"));
        assert!(req.expires_at > req.created_at);
        assert_eq!(req.version, 1);
    }

    #[test]
    fn test_request_hash_uniqueness() {
        let app = test_app();
        let action = Action::Exec {
            argv: vec!["ls".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let r1 = Request::new(app.clone(), action.clone(), None, None);
        let r2 = Request::new(app, action, None, None);

        // Different requests should have different hashes (different nonce + id)
        assert_ne!(r1.request_hash, r2.request_hash);
    }

    #[test]
    fn test_decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Ask.to_string(), "ask");
        assert_eq!(Decision::Deny.to_string(), "deny");
    }

    #[test]
    fn test_request_json_roundtrip() {
        let app = test_app();
        let action = Action::Exec {
            argv: vec!["cargo".to_string(), "test".to_string()],
            cwd: PathBuf::from("/tmp/test"),
            env_requested: vec![],
        };

        let req = Request::new(app, action, None, Some(GrantMode::Once));
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.request_id, req.request_id);
        assert_eq!(parsed.request_hash, req.request_hash);
        assert_eq!(parsed.app.name, "test-agent");
    }

    #[test]
    fn test_response_json_roundtrip() {
        let resp = Response::Escalated {
            request_id: "req_test".to_string(),
            message: "Human approval required".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("escalated"));
    }
}
