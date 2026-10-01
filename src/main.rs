//! `rotate` entry point.
//!
//! This is the only file allowed to write directly to stdout or stderr until
//! the redacted console (SHA-246) exists.

mod cli;
mod exit;
mod providers;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};

use rotate::config::Config;
use rotate::finding::Finding;
use rotate::report::{read_report, ReportError};

use crate::cli::{Cli, Command, InputArgs};
use crate::exit::Exit;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return handle_parse_error(err),
    };
    install_logging(cli.global.verbose);
    // Config errors are usage errors: the operator fixes the file or flag.
    let config = match Config::load(&cli.global.overrides()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {err}");
            return Exit::Usage.into();
        }
    };
    run(cli.subcommand(), &config).into()
}

/// Sends tracing events to stderr through the redaction layer (SHA-218), at
/// the level the `-v` count selects. Installing can only fail if a
/// subscriber is already set, which nothing in this binary does.
fn install_logging(verbose: u8) {
    let level = rotate::redact::level_for(verbose);
    let _ =
        tracing::subscriber::set_global_default(rotate::redact::subscriber(level, std::io::stderr));
}

/// Print a clap error without echoing tokens the user typed.
///
/// clap normally repeats an unrecognized argument in its message. An operator
/// who pastes a secret as an argument instead of using `--stdin` would get it
/// echoed to stderr, so those two error kinds get a fixed message instead.
/// Every other kind (help, version, missing values) prints clap's own text.
/// clap exits 0 for help and version and 2 for errors, which matches
/// `Exit::Ok` and `Exit::Usage`; keep them in step if either changes.
fn handle_parse_error(err: clap::Error) -> ExitCode {
    match err.kind() {
        ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument => {
            let usage = Cli::command().render_usage();
            eprintln!(
                "error: unrecognized argument. Secrets must be passed with --stdin, never as an argument.\n\n{usage}\n\nFor more information, try '--help'."
            );
            Exit::Usage.into()
        }
        _ => err.exit(),
    }
}

fn run(command: Command, _config: &Config) -> Exit {
    if let Some(input) = command.input() {
        match read_input(input) {
            Ok(findings) => print_findings(&findings),
            Err(exit) => return exit,
        }
    }
    // Every subcommand is a stub until its ticket lands (SHA-248 and
    // SHA-250 plan, SHA-254 apply, SHA-259 rollback, SHA-263 status).
    eprintln!("rotate {}: not implemented", command.name());
    Exit::Usage
}

/// Reads the findings named by `input` (SHA-247). Errors are printed here
/// and never include what was read or a path the operator typed: a secret
/// pasted where the report path goes must not be echoed back.
fn read_input(input: &InputArgs) -> Result<Vec<Finding>, Exit> {
    if input.provider.is_some() {
        let registry = providers::registry();
        let known = registry.names();
        if !input
            .provider
            .as_deref()
            .is_some_and(|name| known.contains(&name))
        {
            let known = if known.is_empty() {
                "none are built in yet".to_owned()
            } else {
                known.join(", ")
            };
            eprintln!("error: unknown provider; known providers: {known}");
            return Err(Exit::Usage);
        }
    }

    if input.stdin {
        let stdin = std::io::stdin();
        // The hint is best effort; a closed stderr must not stop the read.
        let _ = rotate::input::stdin_hint(stdin.is_terminal(), &mut std::io::stderr());
        return match rotate::input::read_secret(stdin.lock()) {
            Ok(finding) => Ok(vec![finding]),
            Err(err) => {
                eprintln!("error: {err}");
                Err(Exit::Usage)
            }
        };
    }

    let Some(path) = &input.report else {
        eprintln!("error: no input: pass a report path or --stdin");
        return Err(Exit::Usage);
    };
    match read_report(path, input.format) {
        Ok(report) => {
            for warning in &report.warnings {
                eprintln!("warning: {warning}");
            }
            Ok(report.findings)
        }
        Err(ReportError::Io { source, .. }) => {
            let usage = Cli::command().render_usage();
            eprintln!(
                "error: could not read the report file ({}). Secrets must be passed with --stdin, never as an argument.\n\n{usage}",
                source.kind()
            );
            Err(Exit::Usage)
        }
        Err(err) => {
            eprintln!("error: {err}");
            Err(Exit::Usage)
        }
    }
}

/// Lists what was read, by fingerprint only, until the assessment table
/// replaces it (SHA-248).
fn print_findings(findings: &[Finding]) {
    let noun = if findings.len() == 1 {
        "finding"
    } else {
        "findings"
    };
    println!("{} {noun}:", findings.len());
    for finding in findings {
        println!(
            "  {}  {}  {}",
            finding.fingerprint(),
            finding.detector,
            finding.source
        );
    }
}
