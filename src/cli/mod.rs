pub mod exec;
pub mod init;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aisudo",
    about = "Sudo for AI agents — policy-driven, human-approved authorization",
    version,
    long_about = "aisudo is a local authorization broker for AI agents and automation tools.\nIt gates access to secrets and catches dangerous actions while letting common operations flow."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// First-run setup — create directories, configure Telegram transport
    Init,

    /// Run the authorization daemon (background service)
    Daemon,

    /// Gate a command — request authorization, then execute if approved
    #[command(trailing_var_arg = true)]
    Exec {
        /// The command to authorize and execute
        #[arg(required = true)]
        cmd: Vec<String>,
    },

    /// Send a raw JSON authorization request (reads from stdin or file)
    Request {
        /// Path to JSON file (reads stdin if omitted)
        #[arg(long)]
        json: Option<String>,

        #[command(subcommand)]
        sub: Option<RequestSub>,
    },

    /// Pair a new authorizer device (phone/PWA)
    Pair,

    /// Manage paired devices
    Devices {
        #[command(subcommand)]
        sub: DevicesSub,
    },

    /// Request access to a secret
    Ask {
        #[command(subcommand)]
        sub: AskSub,
    },

    /// Scan filesystem for exposed secrets
    Scan,

    /// Show or manage policy
    Policy {
        #[command(subcommand)]
        sub: Option<PolicySub>,
    },

    /// Manage temporary grants
    Grants {
        #[command(subcommand)]
        sub: Option<GrantsSub>,
    },

    /// Query the audit log
    Audit {
        #[command(subcommand)]
        sub: AuditSub,
    },

    /// Show aisudo daemon status
    Status,
}

#[derive(Subcommand)]
pub enum RequestSub {
    /// Show details of a specific request
    Show {
        /// Request ID
        req_id: String,
    },

    /// List pending requests
    Pending,
}

#[derive(Subcommand)]
pub enum DevicesSub {
    /// List paired devices
    List,

    /// Revoke a paired device
    Revoke {
        /// Device ID to revoke
        device_id: String,
    },
}

#[derive(Subcommand)]
pub enum AskSub {
    /// Request access to a named secret
    Secret {
        /// Secret name (e.g. GITHUB_TOKEN)
        name: String,
    },
}

#[derive(Subcommand)]
pub enum PolicySub {
    /// Show the current active policy
    Show,

    /// Create a policy proposal from a TOML file
    Propose {
        /// Path to proposed policy TOML
        file: String,
    },

    /// Show the diff of a policy proposal
    Diff {
        /// Proposal ID
        proposal_id: String,
    },

    /// Apply a policy proposal (requires human approval)
    Apply {
        /// Proposal ID
        proposal_id: String,
    },

    /// Explain which policy rule matched a request
    Explain {
        /// Request ID
        req_id: String,
    },
}

#[derive(Subcommand)]
pub enum GrantsSub {
    /// List active grants
    List,

    /// Revoke a grant
    Revoke {
        /// Grant ID to revoke
        grant_id: String,
    },
}

#[derive(Subcommand)]
pub enum AuditSub {
    /// Follow the audit log (tail -f style)
    Tail,

    /// Show a specific audit entry
    Show {
        /// Request ID
        req_id: String,
    },
}
