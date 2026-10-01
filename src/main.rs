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

use rotate::assess::{assess, AssessOptions};
use rotate::config::Config;
use rotate::finding::Finding;
use rotate::plan;
use rotate::report::{read_report, ReportError};
use rotate::state::{StateError, StateStore};

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
    let exit = run(cli.subcommand(), &config, cli.global.json);
    providers::finish();
    exit.into()
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

fn run(command: Command, config: &Config, json: bool) -> Exit {
    if let Some(input) = command.input() {
        let findings = match read_input(input) {
            Ok(findings) => findings,
            Err(exit) => return exit,
        };
        if let Command::Plan(_) = command {
            return plan(findings, input, config, json);
        }
    }
    // Still stubs until their tickets land (SHA-254 apply, SHA-259
    // rollback, SHA-263 status).
    eprintln!("rotate {}: not implemented", command.name());
    Exit::Usage
}

/// Builds the plan (SHA-250) and prints the table or JSON: assessment
/// (SHA-248), then `find` on every consumer, then a `planned` record per new
/// rotation in the state file. No state-changing remote call is made.
/// Blockers and skipped rows are information, not failures: exit 0. A held
/// or unusable state file exits 2 before any provider call; a plain I/O
/// error writing it exits 1.
fn plan(findings: Vec<Finding>, input: &InputArgs, config: &Config, json: bool) -> Exit {
    let state_error = |err: StateError| {
        eprintln!("error: {err}");
        if err.is_usage() {
            Exit::Usage
        } else {
            Exit::RotationFailed
        }
    };
    let mut store = match StateStore::open(&config.state_file) {
        Ok(store) => store,
        Err(err) => return state_error(err),
    };
    let registry = providers::registry();
    let consumers = providers::consumers();
    let opts = AssessOptions {
        concurrency: usize::from(input.concurrency),
        force_provider: input
            .provider
            .as_deref()
            .and_then(|name| registry.get(name))
            .map(|provider| provider.name()),
        ..AssessOptions::default()
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("error: could not start the async runtime: {err}");
            return Exit::RotationFailed;
        }
    };
    let mut plan = runtime.block_on(async {
        let assessed = assess(findings, &registry, &opts).await;
        plan::build(
            assessed,
            &registry,
            &consumers,
            config.overlap_window,
            &config.consumers,
        )
        .await
    });
    if let Err(err) = plan::assign_ids(&mut plan, &mut store) {
        return state_error(err);
    }
    drop(store);
    if json {
        println!("{}", plan::render_json(&plan));
    } else {
        print!("{}", plan::render_table(&plan));
    }
    Exit::Ok
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
