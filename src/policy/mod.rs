use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::protocol::{Action, Decision, RiskLevel, Severity};

// ─── Policy Structs ─────────────────────────────────────────────────

/// The complete policy: defaults + rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Default settings
    pub defaults: PolicyDefaults,

    /// Ordered list of rules (first match wins)
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

/// Default policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefaults {
    /// Decision for unknown actions (allow/ask/deny)
    #[serde(default = "default_unknown")]
    pub unknown: String,

    /// Decision for unknown secret access (allow/ask/deny)
    #[serde(default = "default_unknown_secrets")]
    pub unknown_secrets: String,
}

fn default_unknown() -> String {
    "allow".to_string()
}

fn default_unknown_secrets() -> String {
    "ask".to_string()
}

impl Default for PolicyDefaults {
    fn default() -> Self {
        Self {
            unknown: default_unknown(),
            unknown_secrets: default_unknown_secrets(),
        }
    }
}

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable name
    pub name: String,

    /// Match a single action kind
    #[serde(default)]
    pub action: Option<String>,

    /// Match any of these action kinds
    #[serde(default)]
    pub action_any_of: Option<Vec<String>>,

    /// Match a specific app name (or "*" for any)
    #[serde(default)]
    pub app: Option<String>,

    /// Match argv patterns (first element is command, rest are args, "*" is wildcard)
    #[serde(default)]
    pub argv: Option<Vec<String>>,

    /// Match any of these argv patterns
    #[serde(default)]
    pub argv_any_of: Option<Vec<Vec<String>>>,

    /// Match a file path pattern (supports glob-like "**" and "*")
    #[serde(default)]
    pub path: Option<String>,

    /// Match a secret resource name (or "*" for any)
    #[serde(default)]
    pub resource: Option<String>,

    /// Match a specific working directory or prefix
    #[serde(default)]
    pub cwd: Option<String>,

    /// The decision to apply when this rule matches
    pub decision: String,

    /// Risk level classification
    pub risk: String,
}

// ─── Evaluation Result ──────────────────────────────────────────────

/// Result of evaluating a request against the policy
#[derive(Debug)]
pub struct Evaluation {
    /// The decision (allow/alert/ask/deny)
    pub decision: Decision,

    /// Risk level
    pub risk: RiskLevel,

    /// Severity for notification
    pub severity: Severity,

    /// Name of the matched rule (or "default" if none matched)
    pub matched_rule: String,

    /// Human-readable reasons
    pub reasons: Vec<String>,
}

// ─── Policy Engine ──────────────────────────────────────────────────

/// Load policy from a TOML file
pub fn load_policy(path: &Path) -> Result<Policy> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read policy at {}", path.display()))?;

    let policy: Policy = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse policy at {}", path.display()))?;

    Ok(policy)
}

/// Evaluate a request against the policy
pub fn evaluate(policy: &Policy, action: &Action, app_name: &str) -> Evaluation {
    // Try each rule in order
    for rule in &policy.rules {
        if let Some(reasons) = rule_matches(rule, action, app_name) {
            let decision = parse_decision(&rule.decision, policy);
            let risk = parse_risk(&rule.risk);
            let severity = risk_to_severity(risk, &decision);

            return Evaluation {
                decision,
                risk,
                severity,
                matched_rule: rule.name.clone(),
                reasons,
            };
        }
    }

    // No rule matched — use default
    let (decision, severity) = match action {
        Action::Secret { .. } => {
            let d = parse_decision(&policy.defaults.unknown_secrets, policy);
            let s = match d {
                Decision::Ask => Severity::Alert,
                Decision::Deny => Severity::Alert,
                _ => Severity::Info,
            };
            (d, s)
        }
        _ => {
            let d = parse_decision(&policy.defaults.unknown, policy);
            (d, Severity::Info)
        }
    };

    Evaluation {
        decision,
        risk: RiskLevel::Low,
        severity,
        matched_rule: "default".to_string(),
        reasons: vec!["No rule matched, using default".to_string()],
    }
}

/// Check if a rule matches the given action and app
/// Returns Some(reasons) if matched, None if not
fn rule_matches(rule: &PolicyRule, action: &Action, app_name: &str) -> Option<Vec<String>> {
    let mut reasons = Vec::new();

    // Check app name
    if let Some(ref rule_app) = rule.app {
        if rule_app != "*" && rule_app != app_name {
            return None;
        }
    }

    // Check action kind
    let action_kind = action.kind_str();
    if let Some(ref rule_action) = rule.action {
        if rule_action != action_kind {
            return None;
        }
    }
    if let Some(ref rule_actions) = rule.action_any_of {
        if !rule_actions.iter().any(|a| a == action_kind) {
            return None;
        }
    }

    // Check argv for exec actions
    if let Action::Exec { argv, cwd, .. } = action {
        if let Some(ref rule_argv) = rule.argv {
            if !argv_matches(rule_argv, argv) {
                return None;
            }
            reasons.push(format!("command matches pattern: {}", rule_argv.join(" ")));
        }
        if let Some(ref rule_argv_any) = rule.argv_any_of {
            if !rule_argv_any.iter().any(|pattern| argv_matches(pattern, argv)) {
                return None;
            }
            reasons.push("command matches one of the patterns".to_string());
        }
        if let Some(ref rule_cwd) = rule.cwd {
            if !cwd.starts_with(rule_cwd) {
                return None;
            }
        }
    }

    // Check path for file actions
    if let Action::FileRead { path } | Action::FileWrite { path } = action {
        if let Some(ref rule_path) = rule.path {
            if !path_matches(rule_path, &path.to_string_lossy()) {
                return None;
            }
            reasons.push(format!("path matches pattern: {}", rule_path));
        }
    }

    // Check resource for secret actions
    if let Action::Secret { resource, .. } = action {
        if let Some(ref rule_resource) = rule.resource {
            if rule_resource != "*" && rule_resource != resource {
                return None;
            }
            reasons.push(format!("secret matches: {}", resource));
        }
    }

    if reasons.is_empty() {
        reasons.push(format!("matched rule: {}", rule.name));
    }

    Some(reasons)
}

/// Check if argv matches a pattern (supports "*" as wildcard at any position)
fn argv_matches(pattern: &[String], argv: &[String]) -> bool {
    if pattern.is_empty() {
        return argv.is_empty();
    }

    for (i, pat) in pattern.iter().enumerate() {
        if pat == "*" {
            // Wildcard matches rest if it's the last element
            if i == pattern.len() - 1 {
                return true;
            }
            // Otherwise, skip one argv element
            continue;
        }
        if i >= argv.len() {
            return false;
        }
        if pat != &argv[i] {
            return false;
        }
    }

    pattern.len() == argv.len()
}

/// Check if a file path matches a pattern (supports ** and * globs)
fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.replace("~", &dirs_home());
    let path = path.replace("~", &dirs_home());

    // Simple glob matching
    if pattern.contains("**") {
        let prefix = pattern.split("**").next().unwrap_or("");
        return path.starts_with(prefix);
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return path.starts_with(parts[0]) && path.ends_with(parts[1]);
        }
    }

    path == pattern || path.starts_with(&format!("{}/", pattern))
}

fn dirs_home() -> String {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_string_lossy().to_string())
        .unwrap_or_default()
}

fn parse_decision(s: &str, policy: &Policy) -> Decision {
    match s.to_lowercase().as_str() {
        "allow" => Decision::Allow,
        "alert" => Decision::Alert,
        "ask" => Decision::Ask,
        "deny" => Decision::Deny,
        _ => parse_decision(&policy.defaults.unknown, policy),
    }
}

fn parse_risk(s: &str) -> RiskLevel {
    match s.to_lowercase().as_str() {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Medium,
    }
}

fn risk_to_severity(risk: RiskLevel, decision: &Decision) -> Severity {
    match decision {
        Decision::Deny => match risk {
            RiskLevel::Critical => Severity::Critical,
            _ => Severity::Alert,
        },
        Decision::Ask => match risk {
            RiskLevel::Critical => Severity::Critical,
            RiskLevel::High => Severity::Alert,
            _ => Severity::Info,
        },
        _ => Severity::Info,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_policy() -> Policy {
        let toml_str = r#"
[defaults]
unknown = "allow"
unknown_secrets = "ask"

[[rules]]
name = "ask npm install"
action = "exec"
argv_any_of = [
    ["npm", "install", "*"],
    ["pnpm", "install", "*"],
]
decision = "ask"
risk = "high"

[[rules]]
name = "deny sudo"
action = "exec"
argv = ["sudo", "*"]
decision = "deny"
risk = "critical"

[[rules]]
name = "ask github token"
action = "secret"
resource = "GITHUB_TOKEN"
decision = "ask"
risk = "high"

[[rules]]
name = "deny ssh keys"
action_any_of = ["file-read", "file-write"]
path = "~/.ssh/**"
decision = "deny"
risk = "critical"

[[rules]]
name = "allow git status"
action = "exec"
argv = ["git", "status"]
decision = "allow"
risk = "low"
"#;
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn test_policy_parse() {
        let policy = test_policy();
        assert_eq!(policy.rules.len(), 5);
        assert_eq!(policy.defaults.unknown, "allow");
    }

    #[test]
    fn test_evaluate_npm_install() {
        let policy = test_policy();
        let action = Action::Exec {
            argv: vec!["npm".to_string(), "install".to_string(), "express".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.risk, RiskLevel::High);
        assert_eq!(result.matched_rule, "ask npm install");
    }

    #[test]
    fn test_evaluate_pnpm_install() {
        let policy = test_policy();
        let action = Action::Exec {
            argv: vec!["pnpm".to_string(), "install".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_sudo() {
        let policy = test_policy();
        let action = Action::Exec {
            argv: vec!["sudo".to_string(), "rm".to_string(), "-rf".to_string(), "/".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.risk, RiskLevel::Critical);
    }

    #[test]
    fn test_evaluate_github_token() {
        let policy = test_policy();
        let action = Action::Secret {
            resource: "GITHUB_TOKEN".to_string(),
            purpose: None,
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_evaluate_unknown_secret() {
        let policy = test_policy();
        let action = Action::Secret {
            resource: "SOME_OTHER_TOKEN".to_string(),
            purpose: None,
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Ask); // defaults to ask for secrets
    }

    #[test]
    fn test_evaluate_git_status() {
        let policy = test_policy();
        let action = Action::Exec {
            argv: vec!["git".to_string(), "status".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.risk, RiskLevel::Low);
    }

    #[test]
    fn test_evaluate_unknown_command() {
        let policy = test_policy();
        let action = Action::Exec {
            argv: vec!["ls".to_string(), "-la".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let result = evaluate(&policy, &action, "test-agent");
        assert_eq!(result.decision, Decision::Allow); // default unknown = allow
    }

    #[test]
    fn test_argv_matches() {
        assert!(argv_matches(
            &["npm".into(), "install".into(), "*".into()],
            &["npm".into(), "install".into(), "express".into()]
        ));
        assert!(argv_matches(
            &["sudo".into(), "*".into()],
            &["sudo".into(), "rm".into(), "-rf".into()]
        ));
        assert!(!argv_matches(
            &["npm".into(), "install".into()],
            &["npm".into(), "test".into()]
        ));
    }

    #[test]
    fn test_load_policy_from_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let toml = r#"
[defaults]
unknown = "ask"

[[rules]]
name = "test rule"
action = "exec"
argv = ["test"]
decision = "allow"
risk = "low"
"#;
        std::fs::write(tmp.path(), toml).unwrap();
        let policy = load_policy(tmp.path()).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "test rule");
    }

    #[test]
    fn test_load_default_policy() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("default-policy.toml");
        let policy = load_policy(&path).unwrap();
        assert!(!policy.rules.is_empty());
        assert_eq!(policy.defaults.unknown, "allow");
    }
}
