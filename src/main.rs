mod audit;
mod cli;
mod config;
mod crypto;
mod daemon;
mod grants;
mod policy;
mod protocol;
mod secrets;
mod transport;

use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => cli::init::run(),
        Commands::Daemon => daemon::run().await,
        Commands::Exec { cmd } => cli::exec::run(cmd).await,
        Commands::Request { json, sub } => cmd_request(json, sub).await,
        Commands::Pair => cmd_pair().await,
        Commands::Devices { sub } => cmd_devices(sub),
        Commands::Ask { sub } => cmd_ask(sub).await,
        Commands::Scan => cmd_scan(),
        Commands::Policy { sub } => cmd_policy(sub),
        Commands::Grants { sub } => cmd_grants(sub),
        Commands::Audit { sub } => cmd_audit(sub),
        Commands::Status => cmd_status(),
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

async fn cmd_request(json: Option<String>, sub: Option<cli::RequestSub>) -> anyhow::Result<()> {
    match sub {
        Some(cli::RequestSub::Show { req_id }) => {
            cli::exec::show_request(&req_id).await
        }
        Some(cli::RequestSub::Pending) => {
            cli::exec::list_pending().await
        }
        None => {
            cli::exec::send_json(json).await
        }
    }
}

async fn cmd_pair() -> anyhow::Result<()> {
    // Generate pairing code
    let pairing = crypto::create_pairing_request();

    println!("Pair new authorizer device\n");
    println!("Code: {}", pairing.code);
    println!("Expires: 2 minutes");
    println!();
    println!("Scan QR code or open:");
    println!("  aisudo://pair?code={}", pairing.code);
    println!();
    println!("Waiting for device to submit pairing request...");

    // TODO: Listen for pairing submission via socket

    Ok(())
}

fn cmd_devices(sub: cli::DevicesSub) -> anyhow::Result<()> {
    let devices_path = config::devices_path()?;
    let registry = crypto::DeviceRegistry::load(&devices_path)?;

    match sub {
        cli::DevicesSub::List => {
            let active = registry.active_devices();
            if active.is_empty() {
                println!("No paired devices");
            } else {
                println!("Paired devices:\n");
                for device in active {
                    println!("  {} — {}", device.id, device.name);
                    println!("    Role: {}", device.role);
                    println!("    Key:  {}...", &device.public_key[..20]);
                    println!();
                }
            }
            Ok(())
        }
        cli::DevicesSub::Revoke { device_id } => {
            let mut registry = crypto::DeviceRegistry::load(&devices_path)?;
            if registry.revoke(&device_id) {
                registry.save(&devices_path)?;
                println!("Device {} revoked", device_id);
            } else {
                println!("Device not found: {}", device_id);
            }
            Ok(())
        }
    }
}

async fn cmd_ask(sub: cli::AskSub) -> anyhow::Result<()> {
    match sub {
        cli::AskSub::Secret { name } => {
            // Build a secret request
            let socket_path = config::socket_path()?;

            if !socket_path.exists() {
                anyhow::bail!("aisudo daemon is not running");
            }

            let app = protocol::App {
                name: std::env::var("AISUDO_APP_NAME").unwrap_or_else(|_| "aisudo-ask".to_string()),
                pid: std::process::id(),
                cwd: std::env::current_dir()?,
            };

            let action = protocol::Action::Secret {
                resource: name.clone(),
                purpose: Some(format!("Access secret {}", name)),
            };

            let request = protocol::Request::new(app, action, None, None);

            // Connect to daemon
            let stream = tokio::net::UnixStream::connect(&socket_path).await?;
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = tokio::io::BufReader::new(reader);

            // Send request
            let request_json = serde_json::to_string(&request)?;
            tokio::io::AsyncWriteExt::write_all(&mut writer, request_json.as_bytes()).await?;
            tokio::io::AsyncWriteExt::write_all(&mut writer, b"\n").await?;

            // Read response
            let mut response_line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut response_line).await?;

            let response: protocol::Response = serde_json::from_str(&response_line)?;

            match response {
                protocol::Response::Allowed { .. } => {
                    // In a real implementation, we'd fetch the actual secret value
                    println!("Secret {} access allowed", name);
                    println!("(Secret value retrieval not yet implemented)");
                }
                protocol::Response::Denied { reason } => {
                    eprintln!("Secret {} access denied: {}", name, reason);
                    std::process::exit(1);
                }
                protocol::Response::Escalated { request_id, .. } => {
                    eprintln!("Waiting for approval... (request: {})", request_id);

                    // Wait for final decision
                    let mut final_line = String::new();
                    tokio::io::AsyncBufReadExt::read_line(&mut buf_reader, &mut final_line).await?;

                    let final_response: protocol::Response = serde_json::from_str(&final_line)?;

                    match final_response {
                        protocol::Response::Allowed { .. } => {
                            println!("Secret {} access approved", name);
                        }
                        protocol::Response::Denied { reason } => {
                            eprintln!("Secret {} access denied: {}", name, reason);
                            std::process::exit(1);
                        }
                        _ => {
                            eprintln!("Unexpected response");
                            std::process::exit(1);
                        }
                    }
                }
            }

            Ok(())
        }
    }
}

fn cmd_scan() -> anyhow::Result<()> {
    let root = std::env::current_dir()?;
    println!("Scanning {} for exposed secrets...\n", root.display());

    let findings = secrets::scan_directory(&root)?;

    if findings.is_empty() {
        println!("No exposed secrets found");
    } else {
        println!("Found {} potential secrets:\n", findings.len());
        for finding in &findings {
            println!("  {} — {}", finding.path, finding.name);
            if let Some(line) = finding.line {
                println!("    Line: {}", line);
            }
        }
    }

    Ok(())
}

fn cmd_policy(sub: Option<cli::PolicySub>) -> anyhow::Result<()> {
    let policy_path = config::policy_path()?;

    match sub {
        Some(cli::PolicySub::Show) | None => {
            let policy = policy::load_policy(&policy_path)?;
            println!("{}", toml::to_string_pretty(&policy)?);
            Ok(())
        }
        Some(cli::PolicySub::Propose { file }) => {
            // TODO: Create a proposal
            println!("TODO: Create policy proposal from {}", file);
            Ok(())
        }
        Some(cli::PolicySub::Diff { proposal_id }) => {
            // TODO: Show proposal diff
            println!("TODO: Show diff for proposal {}", proposal_id);
            Ok(())
        }
        Some(cli::PolicySub::Apply { proposal_id }) => {
            // TODO: Apply proposal
            println!("TODO: Apply proposal {}", proposal_id);
            Ok(())
        }
        Some(cli::PolicySub::Explain { req_id }) => {
            let log_path = config::audit_path()?;
            if let Some(entry) = audit::find_by_request_id(&log_path, &req_id)? {
                println!("Request: {}", entry.request_id);
                println!("Matched rule: {}", entry.matched_rule);
                println!("Decision: {}", entry.decision);
                println!("Reasons:");
                for reason in &entry.reasons {
                    println!("  • {}", reason);
                }
            } else {
                println!("Request not found: {}", req_id);
            }
            Ok(())
        }
    }
}

fn cmd_grants(sub: Option<cli::GrantsSub>) -> anyhow::Result<()> {
    let grants_path = config::grants_path()?;
    let all_grants = grants::load_grants(&grants_path)?;

    match sub {
        Some(cli::GrantsSub::List) | None => {
            let active: Vec<_> = all_grants.iter().filter(|g| g.is_active()).collect();
            if active.is_empty() {
                println!("No active grants");
            } else {
                println!("Active grants:\n");
                for grant in active {
                    println!("  {}", grant.id);
                    println!("    App: {}", grant.app);
                    println!("    Action: {}", grant.action.kind);
                    println!("    Expires: {}", grant.expires_at);
                    println!();
                }
            }
            Ok(())
        }
        Some(cli::GrantsSub::Revoke { grant_id }) => {
            if grants::revoke_grant(&grants_path, &grant_id)? {
                println!("Grant {} revoked", grant_id);
            } else {
                println!("Grant not found: {}", grant_id);
            }
            Ok(())
        }
    }
}

fn cmd_audit(sub: cli::AuditSub) -> anyhow::Result<()> {
    let log_path = config::audit_path()?;

    match sub {
        cli::AuditSub::Tail => {
            let entries = audit::tail(&log_path, 50)?;
            for entry in entries {
                println!("{}", entry.display());
            }
            Ok(())
        }
        cli::AuditSub::Show { req_id } => {
            if let Some(entry) = audit::find_by_request_id(&log_path, &req_id)? {
                println!("Request:  {}", entry.request_id);
                println!("Time:     {}", entry.timestamp);
                println!("App:      {}", entry.app_name);
                println!("Action:   {}", entry.action_summary);
                println!("Decision: {}", entry.decision);
                println!("Risk:     {}", entry.risk);
                println!("Severity: {}", entry.severity);
                println!("Rule:     {}", entry.matched_rule);
                println!("Reasons:  {}", entry.reasons.join(", "));
            } else {
                println!("Request not found: {}", req_id);
            }
            Ok(())
        }
    }
}

fn cmd_status() -> anyhow::Result<()> {
    let socket_path = config::socket_path()?;
    let daemon_running = socket_path.exists();

    println!("aisudo status\n");
    println!("Daemon: {}", if daemon_running { "running ✓" } else { "not running" });

    // Count devices
    let devices_path = config::devices_path()?;
    if let Ok(registry) = crypto::DeviceRegistry::load(&devices_path) {
        let active = registry.active_devices().len();
        println!("Devices: {}", active);
    }

    // Count grants
    let grants_path = config::grants_path()?;
    if let Ok(all_grants) = grants::load_grants(&grants_path) {
        let active = all_grants.iter().filter(|g| g.is_active()).count();
        println!("Active grants: {}", active);
    }

    // Last audit entry
    let log_path = config::audit_path()?;
    if let Ok(entries) = audit::tail(&log_path, 1) {
        if let Some(last) = entries.first() {
            println!("Last request: {} ({})", last.request_id, last.timestamp);
        }
    }

    Ok(())
}
