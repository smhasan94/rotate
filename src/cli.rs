//! Command-line definition.
//!
//! `plan` is the default subcommand: running `rotate` with no subcommand is
//! the same as `rotate plan`, so the dry run is always the path of least
//! resistance.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use rotate::config::{Overlap, Overrides};
use rotate::report::ReportFormat;

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

/// Where the leaked secrets come from (SHA-247): a scanner report, or a
/// single secret on stdin. Secrets are never accepted as arguments.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct InputArgs {
    /// TruffleHog (JSON lines) or gitleaks (JSON) report to read.
    #[arg(value_name = "REPORT", conflicts_with = "stdin")]
    pub report: Option<PathBuf>,

    /// Report format. Detected from the file when omitted.
    #[arg(long, value_enum, value_name = "FORMAT", requires = "report")]
    pub format: Option<ReportFormat>,

    /// Read one secret from stdin instead of a report. An AWS key pair may
    /// be given as KEY_ID:SECRET or on two lines.
    #[arg(long)]
    pub stdin: bool,

    /// Provider of the stdin secret, skipping identification.
    #[arg(long, value_name = "NAME", requires = "stdin")]
    pub provider: Option<String>,

    /// Most provider checks in flight at once (SHA-248).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_CONCURRENCY,
          value_parser = clap::value_parser!(u16).range(1..=64))]
    pub concurrency: u16,
}

/// Default for `--concurrency`.
pub const DEFAULT_CONCURRENCY: u16 = 8;

impl Default for InputArgs {
    fn default() -> Self {
        Self {
            report: None,
            format: None,
            stdin: false,
            provider: None,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

/// The four workflow commands.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Show what would be created, updated and revoked. Makes no changes.
    Plan(InputArgs),
    /// Create the replacement, update consumers, verify, then revoke.
    Apply(InputArgs),
    /// Restore the previous state where the provider allows it.
    Rollback(InputArgs),
    /// Show in-progress rotations.
    Status,
}

impl Command {
    /// Name as typed on the command line.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Plan(_) => "plan",
            Command::Apply(_) => "apply",
            Command::Rollback(_) => "rollback",
            Command::Status => "status",
        }
    }

    /// The input arguments of a command that reads secrets.
    pub fn input(&self) -> Option<&InputArgs> {
        match self {
            Command::Plan(input) | Command::Apply(input) | Command::Rollback(input) => Some(input),
            Command::Status => None,
        }
    }
}

impl Cli {
    /// The subcommand to run, applying the `plan` default.
    pub fn subcommand(&self) -> Command {
        self.subcommand
            .clone()
            .unwrap_or_else(|| Command::Plan(InputArgs::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_means_plan() {
        let cli = Cli::parse_from(["rotate"]);
        assert_eq!(cli.subcommand(), Command::Plan(InputArgs::default()));
    }

    #[test]
    fn global_flags_parse_without_subcommand() {
        let cli = Cli::parse_from(["rotate", "-vv", "--json"]);
        assert_eq!(cli.global.verbose, 2);
        assert!(cli.global.json);
        assert_eq!(cli.subcommand(), Command::Plan(InputArgs::default()));
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
    fn input_args_parse() {
        let cli = Cli::parse_from(["rotate", "plan", "report.json", "--format", "gitleaks"]);
        let input = cli.subcommand().input().cloned().unwrap();
        assert_eq!(
            input.report.as_deref(),
            Some(std::path::Path::new("report.json"))
        );
        assert_eq!(input.format, Some(ReportFormat::Gitleaks));
        assert!(!input.stdin);

        let cli = Cli::parse_from(["rotate", "apply", "--stdin", "--provider", "aws"]);
        let input = cli.subcommand().input().cloned().unwrap();
        assert!(input.stdin);
        assert_eq!(input.provider.as_deref(), Some("aws"));
        assert_eq!(
            Cli::parse_from(["rotate", "status"]).subcommand().input(),
            None
        );
    }

    #[test]
    fn input_args_conflicts() {
        for args in [
            vec!["rotate", "plan", "r.json", "--stdin"],
            vec!["rotate", "plan", "--provider", "aws"],
            vec!["rotate", "plan", "--format", "gitleaks"],
            vec!["rotate", "plan", "r.json", "--format", "csv"],
            vec!["rotate", "plan", "r.json", "--concurrency", "0"],
            vec!["rotate", "plan", "r.json", "--concurrency", "65"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?} accepted");
        }
    }

    #[test]
    fn clap_definition_is_valid() {
        use clap::CommandFactory;
        <Cli as CommandFactory>::command().debug_assert();
    }
}
