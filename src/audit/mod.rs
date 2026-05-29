use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::protocol::{Decision, Severity};

/// A single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: String,

    /// When the action was processed
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,

    /// Request ID that triggered this entry
    pub request_id: String,

    /// App that made the request
    pub app_name: String,

    /// Action kind (exec, secret, file-read, etc.)
    pub action_kind: String,

    /// Human-readable summary of the action
    pub action_summary: String,

    /// Decision that was made
    pub decision: Decision,

    /// Risk level
    pub risk: String,

    /// Severity of the notification
    pub severity: Severity,

    /// Name of the matched policy rule
    pub matched_rule: String,

    /// Reasons for the decision
    pub reasons: Vec<String>,

    /// Whether the action was actually executed (for exec actions)
    #[serde(default)]
    pub executed: bool,

    /// Exit code if executed
    #[serde(default)]
    pub exit_code: Option<i32>,
}

impl AuditEntry {
    pub fn new(
        request_id: String,
        app_name: String,
        action_kind: String,
        action_summary: String,
        decision: Decision,
        risk: String,
        severity: Severity,
        matched_rule: String,
        reasons: Vec<String>,
    ) -> Self {
        Self {
            id: format!("aud_{}", Ulid::new().to_string().to_lowercase()),
            timestamp: OffsetDateTime::now_utc(),
            request_id,
            app_name,
            action_kind,
            action_summary,
            decision,
            risk,
            severity,
            matched_rule,
            reasons,
            executed: false,
            exit_code: None,
        }
    }

    /// Format for human-readable display
    pub fn display(&self) -> String {
        let time = self.timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        format!(
            "[{}] {} {} ({}) → {} | rule: {} | {}",
            &time[..19],
            self.app_name,
            self.action_summary,
            self.risk,
            self.decision,
            self.matched_rule,
            self.reasons.join(", ")
        )
    }
}

/// Append an entry to the audit log
pub fn append(log_path: &Path, entry: &AuditEntry) -> Result<()> {
    let json = serde_json::to_string(entry)
        .context("Failed to serialize audit entry")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| format!("Failed to open audit log at {}", log_path.display()))?;

    writeln!(file, "{}", json)
        .with_context(|| format!("Failed to write to audit log at {}", log_path.display()))?;

    Ok(())
}

/// Read all audit entries from the log
pub fn read_all(log_path: &Path) -> Result<Vec<AuditEntry>> {
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(log_path)
        .with_context(|| format!("Failed to open audit log at {}", log_path.display()))?;

    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line.context("Failed to read line from audit log")?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                tracing::warn!("Skipping malformed audit log line: {}", e);
            }
        }
    }

    Ok(entries)
}

/// Find an audit entry by request ID
pub fn find_by_request_id(log_path: &Path, request_id: &str) -> Result<Option<AuditEntry>> {
    let entries = read_all(log_path)?;
    Ok(entries.into_iter().find(|e| e.request_id == request_id))
}

/// Tail the audit log (return last N entries)
pub fn tail(log_path: &Path, count: usize) -> Result<Vec<AuditEntry>> {
    let entries = read_all(log_path)?;
    let start = entries.len().saturating_sub(count);
    Ok(entries[start..].to_vec())
}

/// Follow mode: yield new entries as they appear
/// Returns an iterator-like function that blocks on new entries
pub fn follow(log_path: &Path, callback: impl Fn(&AuditEntry)) -> Result<()> {
    let file = fs::File::open(log_path)
        .with_context(|| format!("Failed to open audit log at {}", log_path.display()))?;

    let mut reader = BufReader::new(file);
    let mut line = String::new();

    // Seek to end to only get new entries
    reader.seek(SeekFrom::End(0))?;

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data, wait a bit
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Ok(_) => {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(line.trim()) {
                    callback(&entry);
                }
            }
            Err(e) => {
                tracing::error!("Error reading audit log: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_entry(decision: Decision) -> AuditEntry {
        AuditEntry::new(
            "req_test123".to_string(),
            "test-agent".to_string(),
            "exec".to_string(),
            "pnpm install".to_string(),
            decision,
            "high".to_string(),
            Severity::Alert,
            "ask package managers".to_string(),
            vec!["package manager execution".to_string()],
        )
    }

    #[test]
    fn test_append_and_read() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let entry = make_entry(Decision::Ask);
        append(&log_path, &entry).unwrap();

        let entries = read_all(&log_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].request_id, "req_test123");
        assert_eq!(entries[0].decision, Decision::Ask);
    }

    #[test]
    fn test_multiple_entries() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        append(&log_path, &make_entry(Decision::Allow)).unwrap();
        append(&log_path, &make_entry(Decision::Deny)).unwrap();
        append(&log_path, &make_entry(Decision::Ask)).unwrap();

        let entries = read_all(&log_path).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_find_by_request_id() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let mut entry1 = make_entry(Decision::Allow);
        entry1.request_id = "req_aaa".to_string();
        let mut entry2 = make_entry(Decision::Deny);
        entry2.request_id = "req_bbb".to_string();

        append(&log_path, &entry1).unwrap();
        append(&log_path, &entry2).unwrap();

        let found = find_by_request_id(&log_path, "req_bbb").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().decision, Decision::Deny);

        let not_found = find_by_request_id(&log_path, "req_xxx").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_tail() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        for i in 0..10 {
            let mut entry = make_entry(Decision::Allow);
            entry.request_id = format!("req_{:03}", i);
            append(&log_path, &entry).unwrap();
        }

        let last3 = tail(&log_path, 3).unwrap();
        assert_eq!(last3.len(), 3);
        assert_eq!(last3[0].request_id, "req_007");
        assert_eq!(last3[2].request_id, "req_009");
    }

    #[test]
    fn test_display() {
        let entry = make_entry(Decision::Ask);
        let display = entry.display();
        assert!(display.contains("test-agent"));
        assert!(display.contains("pnpm install"));
        assert!(display.contains("ask"));
    }

    #[test]
    fn test_empty_log() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let entries = read_all(&log_path).unwrap();
        assert!(entries.is_empty());

        let found = find_by_request_id(&log_path, "req_nonexistent").unwrap();
        assert!(found.is_none());
    }
}
