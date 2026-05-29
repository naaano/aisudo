use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::config;
use crate::protocol::{Action, App, GrantMode, Request, Response};

/// Run a command through aisudo (gate + execute)
pub async fn run(args: Vec<String>) -> Result<()> {
    let socket_path = config::socket_path()?;

    if !socket_path.exists() {
        anyhow::bail!(
            "aisudo daemon is not running. Start it with: aisudo daemon"
        );
    }

    // Get current process info
    let app = App {
        name: std::env::var("AISUDO_APP_NAME").unwrap_or_else(|_| "aisudo-exec".to_string()),
        pid: std::process::id(),
        cwd: std::env::current_dir().context("Failed to get current directory")?,
    };

    // Build the action
    let action = Action::Exec {
        argv: args.clone(),
        cwd: app.cwd.clone(),
        env_requested: vec![],
    };

    // Build the request
    let request = Request::new(
        app,
        action,
        Some(format!("Execute: {}", args.join(" "))),
        Some(GrantMode::Once),
    );

    // Connect to daemon
    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("Failed to connect to daemon at {}", socket_path.display()))?;

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Send request
    let request_json = serde_json::to_string(&request)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    // Read response
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    let response: Response = serde_json::from_str(&response_line)
        .context("Failed to parse daemon response")?;

    match response {
        Response::Allowed { grant_id, message } => {
            eprintln!("aisudo: {}", message);
            if let Some(id) = grant_id {
                eprintln!("  grant: {}", id);
            }

            // Execute the command
            let status = std::process::Command::new(&args[0])
                .args(&args[1..])
                .status()
                .with_context(|| format!("Failed to execute: {}", args[0]))?;

            std::process::exit(status.code().unwrap_or(1));
        }
        Response::Denied { reason } => {
            eprintln!("aisudo: denied — {}", reason);
            std::process::exit(1);
        }
        Response::Escalated { request_id, .. } => {
            eprintln!("aisudo: waiting for approval... (request: {})", request_id);
            eprintln!("  Approve on your phone or press Ctrl+C to cancel");

            // Wait for final decision from daemon
            // The daemon will send another response after approval/denial
            let mut final_line = String::new();
            buf_reader.read_line(&mut final_line).await?;

            let final_response: Response = serde_json::from_str(&final_line)
                .context("Failed to parse final daemon response")?;

            match final_response {
                Response::Allowed { message, .. } => {
                    eprintln!("aisudo: {}", message);

                    let status = std::process::Command::new(&args[0])
                        .args(&args[1..])
                        .status()
                        .with_context(|| format!("Failed to execute: {}", args[0]))?;

                    std::process::exit(status.code().unwrap_or(1));
                }
                Response::Denied { reason } => {
                    eprintln!("aisudo: denied — {}", reason);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("aisudo: unexpected response");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Send a raw JSON request to the daemon
pub async fn send_json(json_path: Option<String>) -> Result<()> {
    let socket_path = config::socket_path()?;

    if !socket_path.exists() {
        anyhow::bail!("aisudo daemon is not running");
    }

    // Read the JSON
    let json_str = if let Some(path) = json_path {
        std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path))?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        buf
    };

    let request: Request = serde_json::from_str(&json_str)
        .context("Failed to parse request JSON")?;

    // Connect to daemon
    let stream = UnixStream::connect(&socket_path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Send request
    writer.write_all(json_str.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    // Read response
    let mut response_line = String::new();
    buf_reader.read_line(&mut response_line).await?;

    // Print response
    println!("{}", response_line.trim());

    Ok(())
}

/// List pending requests
pub async fn list_pending() -> Result<()> {
    // For now, we'll use a simple query over the socket
    // In a full implementation, this would be a separate protocol message
    let socket_path = config::socket_path()?;

    if !socket_path.exists() {
        println!("aisudo daemon is not running");
        return Ok(());
    }

    // TODO: Implement proper query protocol
    println!("TODO: Implement pending requests query via socket");

    Ok(())
}

/// Show details of a specific request
pub async fn show_request(request_id: &str) -> Result<()> {
    let log_path = crate::config::audit_path()?;

    match crate::audit::find_by_request_id(&log_path, request_id)? {
        Some(entry) => {
            println!("Request: {}", entry.request_id);
            println!("App:     {}", entry.app_name);
            println!("Action:  {}", entry.action_summary);
            println!("Decision: {}", entry.decision);
            println!("Risk:    {}", entry.risk);
            println!("Rule:    {}", entry.matched_rule);
            println!("Time:    {}", entry.timestamp);
            println!("Reasons: {}", entry.reasons.join(", "));
        }
        None => {
            println!("Request not found: {}", request_id);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request() {
        let app = App {
            name: "test".to_string(),
            pid: 123,
            cwd: PathBuf::from("/tmp"),
        };

        let action = Action::Exec {
            argv: vec!["ls".to_string(), "-la".to_string()],
            cwd: PathBuf::from("/tmp"),
            env_requested: vec![],
        };

        let request = Request::new(app, action, None, Some(GrantMode::Once));
        assert!(request.request_id.starts_with("req_"));
    }
}
