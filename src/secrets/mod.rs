use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ─── Secret Entry ───────────────────────────────────────────────────

/// Metadata about a secret in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Name of the secret (e.g. "GITHUB_TOKEN")
    pub name: String,

    /// Kind of secret (token, api_key, password, ssh_key, etc.)
    #[serde(default = "default_kind")]
    pub kind: String,

    /// Scope/purpose description
    #[serde(default)]
    pub scope: Option<String>,

    /// Risk level (low, medium, high, critical)
    #[serde(default = "default_risk")]
    pub risk: String,

    /// When the secret expires (if applicable)
    #[serde(default)]
    pub expiry: Option<String>,

    /// Where the actual value is stored (keychain, file, etc.)
    #[serde(default = "default_backend")]
    pub backend: String,

    /// Backend-specific reference (e.g. keyring service name)
    #[serde(default)]
    pub backend_ref: Option<String>,
}

fn default_kind() -> String {
    "token".to_string()
}

fn default_risk() -> String {
    "medium".to_string()
}

fn default_backend() -> String {
    "keychain".to_string()
}

// ─── Secret Registry ────────────────────────────────────────────────

/// Registry of known secrets (metadata only, not values)
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SecretRegistry {
    pub secrets: Vec<SecretEntry>,
}

impl SecretRegistry {
    /// Load registry from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read secrets registry at {}", path.display()))?;

        if contents.trim().is_empty() {
            return Ok(Self::default());
        }

        let registry: Self = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse secrets registry at {}", path.display()))?;

        Ok(registry)
    }

    /// Save registry to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize secrets registry")?;

        fs::write(path, contents)
            .with_context(|| format!("Failed to write secrets registry at {}", path.display()))?;

        Ok(())
    }

    /// Find a secret by name
    pub fn find(&self, name: &str) -> Option<&SecretEntry> {
        self.secrets.iter().find(|s| s.name == name)
    }

    /// Add a secret entry
    pub fn add(&mut self, entry: SecretEntry) {
        // Remove existing entry with same name
        self.secrets.retain(|s| s.name != entry.name);
        self.secrets.push(entry);
    }

    /// Remove a secret by name
    pub fn remove(&mut self, name: &str) -> bool {
        let len = self.secrets.len();
        self.secrets.retain(|s| s.name != name);
        self.secrets.len() < len
    }
}

// ─── Secret Backends ────────────────────────────────────────────────

/// Trait for secret value storage backends
pub trait SecretBackend: Send + Sync {
    /// Get a secret value by name
    fn get(&self, name: &str) -> Result<Option<String>>;

    /// Set a secret value
    fn set(&self, name: &str, value: &str) -> Result<()>;

    /// Delete a secret
    fn delete(&self, name: &str) -> Result<bool>;
}

/// macOS Keychain backend
pub struct KeychainBackend {
    service: String,
}

impl KeychainBackend {
    pub fn new() -> Self {
        Self {
            service: "aisudo".to_string(),
        }
    }
}

impl SecretBackend for KeychainBackend {
    fn get(&self, name: &str) -> Result<Option<String>> {
        let entry = keyring::Entry::new(&self.service, name)
            .context("Failed to create keyring entry")?;

        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Keychain error: {}", e)),
        }
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service, name)
            .context("Failed to create keyring entry")?;

        entry.set_password(value)
            .context("Failed to set keychain password")?;

        Ok(())
    }

    fn delete(&self, name: &str) -> Result<bool> {
        let entry = keyring::Entry::new(&self.service, name)
            .context("Failed to create keyring entry")?;

        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(anyhow::anyhow!("Keychain error: {}", e)),
        }
    }
}

/// In-memory backend for testing
pub struct MemoryBackend {
    store: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SecretBackend for MemoryBackend {
    fn get(&self, name: &str) -> Result<Option<String>> {
        let store = self.store.lock().unwrap();
        Ok(store.get(name).cloned())
    }

    fn set(&self, name: &str, value: &str) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<bool> {
        let mut store = self.store.lock().unwrap();
        Ok(store.remove(name).is_some())
    }
}

// ─── Secret Scanner ─────────────────────────────────────────────────

/// Finding from a secret scan
#[derive(Debug)]
pub struct ScanFinding {
    /// File path where the secret was found
    pub path: String,

    /// Type of finding
    pub kind: String,

    /// Name/description of the secret
    pub name: String,

    /// Line number (if applicable)
    pub line: Option<usize>,
}

/// Scan a directory for exposed secrets
pub fn scan_directory(root: &Path) -> Result<Vec<ScanFinding>> {
    let mut findings = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        // Skip hidden dirs/files (except .env)
        if is_hidden(&entry) && !path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.starts_with(".env"))
            .unwrap_or(false)
        {
            continue;
        }

        if !path.is_file() {
            continue;
        }

        // Check .env files
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(".env") {
                findings.push(ScanFinding {
                    path: path.to_string_lossy().to_string(),
                    kind: "env_file".to_string(),
                    name: name.to_string(),
                    line: None,
                });
                continue;
            }
        }

        // Check for hardcoded tokens in source files
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "rs" | "py" | "js" | "ts" | "go" | "rb" | "java" | "toml" | "yaml" | "yml" | "json") {
                if let Ok(content) = fs::read_to_string(path) {
                    for (line_num, line) in content.lines().enumerate() {
                        if let Some(name) = find_hardcoded_secret(line) {
                            findings.push(ScanFinding {
                                path: path.to_string_lossy().to_string(),
                                kind: "hardcoded_secret".to_string(),
                                name,
                                line: Some(line_num + 1),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| {
            // Allow .env files through
            if s.starts_with(".env") {
                return false;
            }
            s.starts_with('.') || s == "target" || s == "node_modules"
        })
        .unwrap_or(false)
}

/// Check a line for hardcoded secrets
fn find_hardcoded_secret(line: &str) -> Option<String> {
    let patterns = [
        ("GITHUB_TOKEN", "github_pat_"),
        ("GITHUB_TOKEN", "ghp_"),
        ("NPM_TOKEN", "npm_"),
        ("AWS_ACCESS_KEY", "AKIA"),
        ("SLACK_TOKEN", "xoxb-"),
        ("SLACK_TOKEN", "xoxp-"),
        ("STRIPE_KEY", "sk_live_"),
        ("STRIPE_KEY", "sk_test_"),
        ("OPENAI_KEY", "sk-"),
        ("API_KEY", "api_key="),
        ("API_KEY", "apiKey="),
        ("SECRET_KEY", "secret="),
        ("SECRET_KEY", "SECRET="),
        ("TOKEN", "token="),
        ("PASSWORD", "password="),
    ];

    let lower = line.to_lowercase();

    for (name, pattern) in &patterns {
        if lower.contains(&pattern.to_lowercase()) {
            return Some(name.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_registry_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.toml");

        let mut registry = SecretRegistry::default();
        registry.add(SecretEntry {
            name: "GITHUB_TOKEN".to_string(),
            kind: "token".to_string(),
            scope: Some("GitHub API access".to_string()),
            risk: "high".to_string(),
            expiry: None,
            backend: "keychain".to_string(),
            backend_ref: None,
        });

        registry.save(&path).unwrap();
        let loaded = SecretRegistry::load(&path).unwrap();

        assert_eq!(loaded.secrets.len(), 1);
        assert_eq!(loaded.secrets[0].name, "GITHUB_TOKEN");
    }

    #[test]
    fn test_registry_find() {
        let mut registry = SecretRegistry::default();
        registry.add(SecretEntry {
            name: "MY_TOKEN".to_string(),
            ..Default::default()
        });

        assert!(registry.find("MY_TOKEN").is_some());
        assert!(registry.find("OTHER_TOKEN").is_none());
    }

    #[test]
    fn test_registry_remove() {
        let mut registry = SecretRegistry::default();
        registry.add(SecretEntry {
            name: "MY_TOKEN".to_string(),
            ..Default::default()
        });

        assert!(registry.remove("MY_TOKEN"));
        assert!(!registry.remove("MY_TOKEN"));
        assert!(registry.secrets.is_empty());
    }

    #[test]
    fn test_memory_backend() {
        let backend = MemoryBackend::new();

        assert!(backend.get("test").unwrap().is_none());

        backend.set("test", "value123").unwrap();
        assert_eq!(backend.get("test").unwrap(), Some("value123".to_string()));

        assert!(backend.delete("test").unwrap());
        assert!(backend.get("test").unwrap().is_none());
    }

    #[test]
    fn test_scan_directory() {
        let tmp = TempDir::new().unwrap();

        // Create .env file
        fs::write(tmp.path().join(".env"), "SECRET=abc123").unwrap();

        // Create a file with hardcoded secret
        fs::write(
            tmp.path().join("config.rs"),
            r#"const API_KEY: &str = "sk-test-12345";"#,
        )
        .unwrap();

        // Create a safe file
        fs::write(tmp.path().join("main.rs"), "fn main() {}").unwrap();

        let findings = scan_directory(tmp.path()).unwrap();

        // Should find .env and hardcoded secret
        assert!(findings.iter().any(|f| f.kind == "env_file"), "Expected env_file finding");
        assert!(findings.iter().any(|f| f.kind == "hardcoded_secret"), "Expected hardcoded_secret finding");
    }

    #[test]
    fn test_find_hardcoded_secret() {
        assert!(find_hardcoded_secret("GITHUB_TOKEN=ghp_abc123").is_some());
        assert!(find_hardcoded_secret("const API_KEY = \"sk-test\"").is_some());
        assert!(find_hardcoded_secret("let x = 42;").is_none());
    }

    #[test]
    fn test_empty_registry() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.toml");

        let registry = SecretRegistry::load(&path).unwrap();
        assert!(registry.secrets.is_empty());
    }
}

impl Default for SecretEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: default_kind(),
            scope: None,
            risk: default_risk(),
            expiry: None,
            backend: default_backend(),
            backend_ref: None,
        }
    }
}
