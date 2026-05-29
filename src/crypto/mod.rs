use anyhow::{Context, Result};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use time::OffsetDateTime;
use ulid::Ulid;

// ─── Device ─────────────────────────────────────────────────────────

/// A paired authorizer device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique device ID
    pub id: String,

    /// Human-readable device name
    pub name: String,

    /// Ed25519 public key (base64 encoded)
    pub public_key: String,

    /// Device role (owner, viewer)
    #[serde(default = "default_role")]
    pub role: String,

    /// Device capabilities
    #[serde(default)]
    pub capabilities: DeviceCapabilities,

    /// When the device was paired
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// Last time the device was seen
    #[serde(default)]
    pub last_seen_at: Option<String>,

    /// If revoked, when
    #[serde(default)]
    pub revoked_at: Option<String>,
}

fn default_role() -> String {
    "owner".to_string()
}

/// Device capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// Maximum risk level this device can approve
    #[serde(default)]
    pub approve_risk: Vec<String>,

    /// Can change policy
    #[serde(default)]
    pub change_policy: bool,

    /// Can view full audit log
    #[serde(default)]
    pub view_full_audit: bool,

    /// Can view policy
    #[serde(default)]
    pub view_policy: bool,

    /// Can view secrets (metadata only)
    #[serde(default)]
    pub view_secrets: bool,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        Self {
            approve_risk: vec!["low".to_string(), "medium".to_string(), "high".to_string()],
            change_policy: true,
            view_full_audit: true,
            view_policy: true,
            view_secrets: false,
        }
    }
}

// ─── Device Registry ────────────────────────────────────────────────

/// Device registry storage
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DeviceRegistry {
    pub devices: Vec<Device>,
}

impl DeviceRegistry {
    /// Load registry from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read devices at {}", path.display()))?;

        if contents.trim().is_empty() {
            return Ok(Self::default());
        }

        let registry: Self = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse devices at {}", path.display()))?;

        Ok(registry)
    }

    /// Save registry to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .context("Failed to serialize devices")?;

        fs::write(path, contents)
            .with_context(|| format!("Failed to write devices at {}", path.display()))?;

        Ok(())
    }

    /// Add a device
    pub fn add(&mut self, device: Device) {
        self.devices.push(device);
    }

    /// Find a device by ID
    pub fn find(&self, id: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == id)
    }

    /// Find a device by public key
    pub fn find_by_key(&self, public_key: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.public_key == public_key && d.revoked_at.is_none())
    }

    /// Revoke a device
    pub fn revoke(&mut self, id: &str) -> bool {
        if let Some(device) = self.devices.iter_mut().find(|d| d.id == id) {
            device.revoked_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
            true
        } else {
            false
        }
    }

    /// List active (non-revoked) devices
    pub fn active_devices(&self) -> Vec<&Device> {
        self.devices.iter().filter(|d| d.revoked_at.is_none()).collect()
    }
}

// ─── Crypto Operations ──────────────────────────────────────────────

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Encode a public key as base64
pub fn encode_public_key(key: &VerifyingKey) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes())
}

/// Decode a public key from base64
pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .context("Invalid base64 public key")?;

    let key_bytes: [u8; 32] = bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))
}

/// Sign a message with a signing key
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> String {
    let signature = signing_key.sign(message);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signature.to_bytes())
}

/// Verify a signature
pub fn verify_signature(
    public_key: &VerifyingKey,
    message: &[u8],
    signature_b64: &str,
) -> Result<bool> {
    let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
        .context("Invalid base64 signature")?;

    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid signature: {}", e))?;

    Ok(public_key.verify(message, &signature).is_ok())
}

// ─── Pairing ────────────────────────────────────────────────────────

/// A pending pairing request
#[derive(Debug, Clone)]
pub struct PairingRequest {
    /// Short pairing code
    pub code: String,

    /// When it was created
    pub created_at: OffsetDateTime,

    /// When it expires
    pub expires_at: OffsetDateTime,
}

/// Generate a pairing code
pub fn generate_pairing_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(100000..999999);
    format!("{}-{}", code / 1000, code % 1000)
}

/// Create a new pairing request
pub fn create_pairing_request() -> PairingRequest {
    let now = OffsetDateTime::now_utc();
    PairingRequest {
        code: generate_pairing_code(),
        created_at: now,
        expires_at: now + time::Duration::seconds(120), // 2 minutes
    }
}

/// Check if a pairing request is still valid
pub fn is_pairing_valid(request: &PairingRequest) -> bool {
    request.expires_at > OffsetDateTime::now_utc()
}

/// Compute fingerprint of a public key
pub fn key_fingerprint(public_key: &VerifyingKey) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(public_key.as_bytes());
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash.as_slice());
    format!("SHA256:{}", &encoded[..20])
}

// ─── Nonce Tracking ─────────────────────────────────────────────────

/// Simple nonce store for replay protection
#[derive(Debug, Default)]
pub struct NonceStore {
    used_nonces: std::collections::HashSet<String>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a nonce has been used, and mark it as used
    pub fn check_and_use(&mut self, nonce: &str) -> bool {
        if self.used_nonces.contains(nonce) {
            return false; // Already used
        }
        self.used_nonces.insert(nonce.to_string());
        true
    }

    /// Check if a nonce has been used (without marking)
    pub fn is_used(&self, nonce: &str) -> bool {
        self.used_nonces.contains(nonce)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_keypair_generation() {
        let (signing_key, verifying_key) = generate_keypair();
        let encoded = encode_public_key(&verifying_key);
        assert!(!encoded.is_empty());

        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(verifying_key, decoded);
    }

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message";

        let signature = sign_message(&signing_key, message);
        assert!(verify_signature(&verifying_key, message, &signature).unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = sign_message(&signing_key, message);
        assert!(!verify_signature(&verifying_key, wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_pairing_code() {
        let code = generate_pairing_code();
        assert!(code.len() >= 5 && code.len() <= 7, "Code length should be 5-7, got {}", code.len());
        assert!(code.contains('-'));
    }

    #[test]
    fn test_pairing_request() {
        let request = create_pairing_request();
        assert!(is_pairing_valid(&request));
        assert!(!request.code.is_empty());
    }

    #[test]
    fn test_key_fingerprint() {
        let (_, verifying_key) = generate_keypair();
        let fp = key_fingerprint(&verifying_key);
        assert!(fp.starts_with("SHA256:"));
    }

    #[test]
    fn test_nonce_store() {
        let mut store = NonceStore::new();

        assert!(store.check_and_use("nonce1"));
        assert!(!store.check_and_use("nonce1")); // Already used
        assert!(store.is_used("nonce1"));
        assert!(!store.is_used("nonce2"));
    }

    #[test]
    fn test_device_registry_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devices.toml");

        let (_, verifying_key) = generate_keypair();
        let device = Device {
            id: "device_test".to_string(),
            name: "Test iPhone".to_string(),
            public_key: encode_public_key(&verifying_key),
            role: "owner".to_string(),
            capabilities: DeviceCapabilities::default(),
            created_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            revoked_at: None,
        };

        let mut registry = DeviceRegistry::default();
        registry.add(device);
        registry.save(&path).unwrap();

        let loaded = DeviceRegistry::load(&path).unwrap();
        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.devices[0].name, "Test iPhone");
    }

    #[test]
    fn test_device_revoke() {
        let mut registry = DeviceRegistry::default();
        let (_, verifying_key) = generate_keypair();

        registry.add(Device {
            id: "device_1".to_string(),
            name: "Test".to_string(),
            public_key: encode_public_key(&verifying_key),
            role: "owner".to_string(),
            capabilities: DeviceCapabilities::default(),
            created_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            revoked_at: None,
        });

        assert_eq!(registry.active_devices().len(), 1);

        registry.revoke("device_1");
        assert_eq!(registry.active_devices().len(), 0);
    }

    #[test]
    fn test_find_by_key() {
        let mut registry = DeviceRegistry::default();
        let (_, verifying_key) = generate_keypair();
        let key_b64 = encode_public_key(&verifying_key);

        registry.add(Device {
            id: "device_1".to_string(),
            name: "Test".to_string(),
            public_key: key_b64.clone(),
            role: "owner".to_string(),
            capabilities: DeviceCapabilities::default(),
            created_at: OffsetDateTime::now_utc(),
            last_seen_at: None,
            revoked_at: None,
        });

        assert!(registry.find_by_key(&key_b64).is_some());
        assert!(registry.find_by_key("nonexistent").is_none());
    }
}
