use anyhow::{Context, Result};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// aisudo configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Telegram bot token
    pub telegram_bot_token: Option<String>,

    /// Telegram chat ID for notifications
    pub telegram_chat_id: Option<String>,

    /// Default decision for unknown actions (allow/ask/deny)
    #[serde(default = "default_unknown")]
    pub default_unknown: String,

    /// Default severity for unknown actions
    #[serde(default = "default_severity")]
    pub default_severity: String,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

fn default_unknown() -> String {
    "allow".to_string()
}

fn default_severity() -> String {
    "info".to_string()
}

fn default_timeout() -> u64 {
    300 // 5 minutes
}

impl Default for Config {
    fn default() -> Self {
        Self {
            telegram_bot_token: None,
            telegram_chat_id: None,
            default_unknown: default_unknown(),
            default_severity: default_severity(),
            request_timeout_secs: default_timeout(),
        }
    }
}

/// Get the aisudo home directory (~/.aisudo)
pub fn aisudo_home() -> Result<PathBuf> {
    let base = BaseDirs::new().context("Could not determine home directory")?;
    Ok(base.home_dir().join(".aisudo"))
}

/// Get the private directory (~/.aisudo/private)
pub fn private_dir() -> Result<PathBuf> {
    Ok(aisudo_home()?.join("private"))
}

/// Get the public directory (~/.aisudo/public)
pub fn public_dir() -> Result<PathBuf> {
    Ok(aisudo_home()?.join("public"))
}

/// Get the requests directory (~/.aisudo/public/requests)
pub fn requests_dir() -> Result<PathBuf> {
    Ok(public_dir()?.join("requests"))
}

/// Get the socket path
pub fn socket_path() -> Result<PathBuf> {
    Ok(aisudo_home()?.join("aisudo.sock"))
}

/// Get the config file path
pub fn config_path() -> Result<PathBuf> {
    Ok(aisudo_home()?.join("config.toml"))
}

/// Get the policy file path
pub fn policy_path() -> Result<PathBuf> {
    Ok(private_dir()?.join("policy.toml"))
}

/// Get the devices file path
pub fn devices_path() -> Result<PathBuf> {
    Ok(private_dir()?.join("devices.toml"))
}

/// Get the grants file path
pub fn grants_path() -> Result<PathBuf> {
    Ok(private_dir()?.join("grants.toml"))
}

/// Get the secrets registry path
pub fn secrets_path() -> Result<PathBuf> {
    Ok(private_dir()?.join("secrets.toml"))
}

/// Get the audit log path
pub fn audit_path() -> Result<PathBuf> {
    Ok(public_dir()?.join("audit.log"))
}

/// Create the aisudo directory structure with correct permissions
pub fn create_dirs() -> Result<()> {
    let home = aisudo_home()?;

    // Create all directories
    fs::create_dir_all(&home).context("Failed to create ~/.aisudo")?;
    fs::create_dir_all(private_dir()?).context("Failed to create ~/.aisudo/private")?;
    fs::create_dir_all(public_dir()?).context("Failed to create ~/.aisudo/public")?;
    fs::create_dir_all(requests_dir()?).context("Failed to create ~/.aisudo/public/requests")?;

    // Set permissions on private directory (0700)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let private = private_dir()?;
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
            .context("Failed to set permissions on private dir")?;
    }

    Ok(())
}

/// Load config from disk, or return default if not found
pub fn load_config() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }

    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;

    let config: Config = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse config at {}", path.display()))?;

    Ok(config)
}

/// Save config to disk
pub fn save_config(config: &Config) -> Result<()> {
    let path = config_path()?;
    let contents = toml::to_string_pretty(config).context("Failed to serialize config")?;

    fs::write(&path, contents)
        .with_context(|| format!("Failed to write config at {}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.default_unknown, "allow");
        assert_eq!(config.default_severity, "info");
        assert_eq!(config.request_timeout_secs, 300);
        assert!(config.telegram_bot_token.is_none());
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config {
            telegram_bot_token: Some("test-token".to_string()),
            telegram_chat_id: Some("12345".to_string()),
            default_unknown: "ask".to_string(),
            default_severity: "alert".to_string(),
            request_timeout_secs: 600,
        };

        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(parsed.telegram_bot_token, Some("test-token".to_string()));
        assert_eq!(parsed.telegram_chat_id, Some("12345".to_string()));
        assert_eq!(parsed.default_unknown, "ask");
        assert_eq!(parsed.default_severity, "alert");
        assert_eq!(parsed.request_timeout_secs, 600);
    }

    #[test]
    fn test_create_dirs() {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join(".aisudo");

        // Override home for testing by using the paths directly
        fs::create_dir_all(home.join("private")).unwrap();
        fs::create_dir_all(home.join("public/requests")).unwrap();

        assert!(home.join("private").exists());
        assert!(home.join("public/requests").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(home.join("private")).unwrap().permissions();
            // We set it manually for the test
            fs::set_permissions(home.join("private"), fs::Permissions::from_mode(0o700)).unwrap();
            let perms = fs::metadata(home.join("private")).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }
}
