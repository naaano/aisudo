use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::protocol::Action;

/// Scope of a grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantScope {
    /// Workspace path restriction
    #[serde(default)]
    pub workspace: Option<String>,

    /// Only match the exact action
    #[serde(default)]
    pub exact_action_only: bool,
}

/// A temporary or scoped auto-approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Unique grant ID
    pub id: String,

    /// When the grant was created
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// When the grant expires
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,

    /// Device that created this grant
    pub created_by_device: Option<String>,

    /// App this grant applies to
    pub app: String,

    /// Action this grant applies to
    pub action: GrantAction,

    /// Scope restrictions
    pub scope: GrantScope,

    /// If revoked, when it was revoked
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// Action filter for a grant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAction {
    /// Action kind
    pub kind: String,

    /// Hash of the argv (for exec actions)
    #[serde(default)]
    pub argv_hash: Option<String>,

    /// Working directory
    #[serde(default)]
    pub cwd: Option<String>,

    /// Secret resource name (for secret actions)
    #[serde(default)]
    pub resource: Option<String>,
}

impl Grant {
    /// Create a new one-time grant (expires immediately after use)
    pub fn new_once(app: &str, action: &Action, device_id: Option<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: format!("grant_{}", Ulid::new().to_string().to_lowercase()),
            created_at: now,
            expires_at: now + time::Duration::seconds(300), // 5 min
            created_by_device: device_id,
            app: app.to_string(),
            action: GrantAction::from_action(action),
            scope: GrantScope {
                workspace: None,
                exact_action_only: true,
            },
            revoked_at: None,
        }
    }

    /// Create a scoped grant with duration
    pub fn new_for_duration(
        app: &str,
        action: &Action,
        duration_secs: i64,
        device_id: Option<String>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: format!("grant_{}", Ulid::new().to_string().to_lowercase()),
            created_at: now,
            expires_at: now + time::Duration::seconds(duration_secs),
            created_by_device: device_id,
            app: app.to_string(),
            action: GrantAction::from_action(action),
            scope: GrantScope {
                workspace: None,
                exact_action_only: false,
            },
            revoked_at: None,
        }
    }

    /// Check if this grant is still active
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && self.expires_at > OffsetDateTime::now_utc()
    }

    /// Check if this grant matches a given request
    pub fn matches(&self, app_name: &str, action: &Action) -> bool {
        if !self.is_active() {
            return false;
        }

        if self.app != app_name && self.app != "*" {
            return false;
        }

        self.action.matches(action)
    }
}

impl GrantAction {
    fn from_action(action: &Action) -> Self {
        match action {
            Action::Exec { argv, cwd, .. } => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(argv.join(" ").as_bytes());
                let argv_hash = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    hash.as_slice(),
                );

                Self {
                    kind: "exec".to_string(),
                    argv_hash: Some(argv_hash),
                    cwd: Some(cwd.to_string_lossy().to_string()),
                    resource: None,
                }
            }
            Action::Secret { resource, .. } => Self {
                kind: "secret".to_string(),
                argv_hash: None,
                cwd: None,
                resource: Some(resource.clone()),
            },
            Action::FileRead { path } | Action::FileWrite { path } => Self {
                kind: action.kind_str().to_string(),
                argv_hash: None,
                cwd: Some(path.to_string_lossy().to_string()),
                resource: None,
            },
            Action::Network { target, .. } => Self {
                kind: "network".to_string(),
                argv_hash: None,
                cwd: Some(target.clone()),
                resource: None,
            },
        }
    }

    fn matches(&self, action: &Action) -> bool {
        if self.kind != action.kind_str() {
            return false;
        }

        match action {
            Action::Exec { argv, cwd, .. } => {
                if let Some(ref expected_cwd) = self.cwd {
                    if cwd.to_string_lossy() != *expected_cwd {
                        return false;
                    }
                }
                if let Some(ref expected_hash) = self.argv_hash {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(argv.join(" ").as_bytes());
                    let actual_hash = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        hash.as_slice(),
                    );
                    return actual_hash == *expected_hash;
                }
                true
            }
            Action::Secret { resource, .. } => {
                if let Some(ref expected) = self.resource {
                    return expected == resource || expected == "*";
                }
                true
            }
            _ => true,
        }
    }
}

// ─── Storage ────────────────────────────────────────────────────────

/// Load grants from a TOML file
pub fn load_grants(path: &Path) -> Result<Vec<Grant>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read grants at {}", path.display()))?;

    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }

    let wrapper: GrantFile = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse grants at {}", path.display()))?;

    Ok(wrapper.grants)
}

/// Save grants to a TOML file
pub fn save_grants(path: &Path, grants: &[Grant]) -> Result<()> {
    let wrapper = GrantFile {
        grants: grants.to_vec(),
    };
    let contents = toml::to_string_pretty(&wrapper)
        .context("Failed to serialize grants")?;

    fs::write(path, contents)
        .with_context(|| format!("Failed to write grants at {}", path.display()))?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct GrantFile {
    grants: Vec<Grant>,
}

/// Find a matching grant for a request
pub fn find_matching(grants: &[Grant], app_name: &str, action: &Action) -> Option<Grant> {
    grants.iter().find(|g| g.matches(app_name, action)).cloned()
}

/// Add a grant and save
pub fn add_grant(path: &Path, grant: Grant) -> Result<()> {
    let mut grants = load_grants(path)?;
    grants.push(grant);
    save_grants(path, &grants)
}

/// Revoke a grant by ID
pub fn revoke_grant(path: &Path, grant_id: &str) -> Result<bool> {
    let mut grants = load_grants(path)?;
    let mut found = false;

    for grant in &mut grants {
        if grant.id == grant_id {
            grant.revoked_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
            found = true;
            break;
        }
    }

    if found {
        save_grants(path, &grants)?;
    }

    Ok(found)
}

/// Remove expired grants (cleanup)
pub fn cleanup_expired(path: &Path) -> Result<usize> {
    let grants = load_grants(path)?;
    let now = OffsetDateTime::now_utc();
    let original_count = grants.len();

    let active: Vec<Grant> = grants
        .into_iter()
        .filter(|g| g.revoked_at.is_none() && g.expires_at > now)
        .collect();

    save_grants(path, &active)?;
    Ok(original_count - active.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_action() -> Action {
        Action::Exec {
            argv: vec!["pnpm".to_string(), "install".to_string()],
            cwd: PathBuf::from("/tmp/test"),
            env_requested: vec![],
        }
    }

    #[test]
    fn test_grant_creation() {
        let action = test_action();
        let grant = Grant::new_once("test-agent", &action, None);

        assert!(grant.id.starts_with("grant_"));
        assert!(grant.is_active());
        assert!(grant.matches("test-agent", &action));
    }

    #[test]
    fn test_grant_expiry() {
        let action = test_action();
        let mut grant = Grant::new_once("test-agent", &action, None);

        // Set expiry to the past
        grant.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);
        assert!(!grant.is_active());
        assert!(!grant.matches("test-agent", &action));
    }

    #[test]
    fn test_grant_revocation() {
        let action = test_action();
        let mut grant = Grant::new_once("test-agent", &action, None);

        grant.revoked_at = Some("2026-01-01T00:00:00Z".to_string());
        assert!(!grant.is_active());
    }

    #[test]
    fn test_grant_app_mismatch() {
        let action = test_action();
        let grant = Grant::new_once("agent-a", &action, None);

        assert!(!grant.matches("agent-b", &action));
    }

    #[test]
    fn test_grant_save_load_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("grants.toml");

        let action = test_action();
        let grant = Grant::new_once("test-agent", &action, None);

        save_grants(&path, &[grant]).unwrap();
        let loaded = load_grants(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].app, "test-agent");
        assert!(loaded[0].is_active());
    }

    #[test]
    fn test_find_matching_grant() {
        let action = test_action();
        let grants = vec![
            Grant::new_once("other-agent", &action, None),
            Grant::new_once("test-agent", &action, None),
        ];

        let found = find_matching(&grants, "test-agent", &action);
        assert!(found.is_some());
        assert_eq!(found.unwrap().app, "test-agent");
    }

    #[test]
    fn test_revoke_grant() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("grants.toml");

        let action = test_action();
        let grant = Grant::new_once("test-agent", &action, None);
        let grant_id = grant.id.clone();

        save_grants(&path, &[grant]).unwrap();
        let revoked = revoke_grant(&path, &grant_id).unwrap();
        assert!(revoked);

        let loaded = load_grants(&path).unwrap();
        assert!(!loaded[0].is_active());
        assert!(loaded[0].revoked_at.is_some());
    }

    #[test]
    fn test_cleanup_expired() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("grants.toml");

        let action = test_action();
        let mut expired_grant = Grant::new_once("test-agent", &action, None);
        expired_grant.expires_at = OffsetDateTime::now_utc() - time::Duration::hours(1);

        let active_grant = Grant::new_once("test-agent", &action, None);

        save_grants(&path, &[expired_grant, active_grant]).unwrap();
        let removed = cleanup_expired(&path).unwrap();
        assert_eq!(removed, 1);

        let loaded = load_grants(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].is_active());
    }

    #[test]
    fn test_empty_grants_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("grants.toml");

        let grants = load_grants(&path).unwrap();
        assert!(grants.is_empty());
    }
}
