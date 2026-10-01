//! Command-line definition.
//!
//! `plan` is the default subcommand: running `rotate` with no subcommand is
//! the same as `rotate plan`, so the dry run is always the path of least
//! resistance.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use rotate::config::{Overlap, Overrides};

/// Revoke and rotate leaked secrets safely, end to end.
#[derive(Debug, Parser)]
#[command(name = "rotate", version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    /// Subcommand to run. Defaults to `plan`.
    #[command(subcommand)]
    pub subcommand: Option<Command>,
}

/// Flags accepted before or after any subcommand.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Path to rotate.yaml. Defaults to ./rotate.yaml when present.
    #[arg(long, global = true, env = "ROTATE_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Emit machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity. Repeat for more detail.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Audit log path. Overrides ROTATE_AUDIT_LOG and rotate.yaml.
    #[arg(long, global = true, value_name = "PATH")]
    pub audit_log: Option<PathBuf>,

    /// Rotation state file path. Overrides ROTATE_STATE_FILE and rotate.yaml.
    #[arg(long, global = true, value_name = "PATH")]
    pub state_file: Option<PathBuf>,

    /// Time between updating consumers and revoking the old secret, such as
    /// 30m or 1h30m. Overrides ROTATE_OVERLAP and rotate.yaml.
    #[arg(long, global = true, value_name = "DURATION")]
    pub overlap: Option<Overlap>,
}

impl GlobalArgs {
    /// The command-line half of config resolution.
    pub fn overrides(&self) -> Overrides {
        Overrides {
            config: self.config.clone(),
            audit_log: self.audit_log.clone(),
            state_file: self.state_file.clone(),
            overlap_window: self.overlap,
        }
    }
}

/// The four workflow commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Show what would be created, updated and revoked. Makes no changes.
    Plan,
    /// Create the replacement, update consumers, verify, then revoke.
    Apply,
    /// Restore the previous state where the provider allows it.
    Rollback,
    /// Show in-progress rotations.
    Status,
}

impl Command {
    /// Name as typed on the command line.
    pub fn name(self) -> &'static str {
        match self {
            Command::Plan => "plan",
            Command::Apply => "apply",
            Command::Rollback => "rollback",
            Command::Status => "status",
        }
    }
}

impl Cli {
    /// The subcommand to run, applying the `plan` default.
    pub fn subcommand(&self) -> Command {
        self.subcommand.unwrap_or(Command::Plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_means_plan() {
        let cli = Cli::parse_from(["rotate"]);
        assert_eq!(cli.subcommand(), Command::Plan);
    }

    #[test]
    fn global_flags_parse_without_subcommand() {
        let cli = Cli::parse_from(["rotate", "-vv", "--json"]);
        assert_eq!(cli.global.verbose, 2);
        assert!(cli.global.json);
        assert_eq!(cli.subcommand(), Command::Plan);
    }

    #[test]
    fn global_flags_parse_after_subcommand() {
        let cli = Cli::parse_from(["rotate", "status", "--json", "--config", "x.yaml"]);
        assert_eq!(cli.subcommand(), Command::Status);
        assert!(cli.global.json);
        assert_eq!(
            cli.global.config.as_deref(),
            Some(std::path::Path::new("x.yaml"))
        );
    }

    #[test]
    fn config_flags_become_overrides() {
        let cli = Cli::parse_from([
            "rotate",
            "plan",
            "--audit-log",
            "a.jsonl",
            "--state-file",
            "s.json",
            "--overlap",
            "90m",
        ]);
        let overrides = cli.global.overrides();
        assert_eq!(
            overrides.audit_log.as_deref(),
            Some(std::path::Path::new("a.jsonl"))
        );
        assert_eq!(
            overrides.state_file.as_deref(),
            Some(std::path::Path::new("s.json"))
        );
        assert_eq!(overrides.overlap_window.unwrap().to_string(), "1h30m");
        assert!(Cli::try_parse_from(["rotate", "--overlap", "soon"]).is_err());
    }

    #[test]
    fn clap_definition_is_valid() {
        use clap::CommandFactory;
        <Cli as CommandFactory>::command().debug_assert();
    }
}
