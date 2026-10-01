//! `rotate` entry point.
//!
//! Every byte this binary prints goes through `rotate::console::Console`,
//! which redacts it (SHA-246). `clippy.toml` rejects `println!` and friends.

mod cli;
mod exit;
mod providers;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use rotate::assess::{assess, AssessOptions};
use rotate::config::{Config, ConfigError};
use rotate::console::{self, Console};
use rotate::finding::Finding;
use rotate::plan;
use rotate::report::{read_report, ReportError};
use rotate::state::{StateError, StateStore};

use crate::cli::{Cli, Command, InputArgs};
use crate::exit::Exit;

fn main() -> ExitCode {
    console::install_panic_hook();
    let mut console = Console::stdio();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let usage = Cli::command().render_usage();
            let code = console.report_parse_error(&err, &usage);
            return ExitCode::from(u8::try_from(code).unwrap_or(Exit::Usage as u8));
        }
    };
    install_logging(cli.global.verbose);
    // Config errors are usage errors: the operator fixes the file or flag.
    let config = match Config::load(&cli.global.overrides()) {
        Ok(config) => config,
        Err(ConfigError::Read { source, .. }) => {
            // The path may be something the operator typed, such as a token
            // pasted after --config, so it is not repeated.
            let _ = writeln!(
                console.err(),
                "error: could not read the config file ({}). Secrets must be passed with --stdin, never as an argument.",
                source.kind()
            );
            return Exit::Usage.into();
        }
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            return Exit::Usage.into();
        }
    };
    // A secret read for the hidden test command lives until its error has
    // been printed, as real inputs must: a value is redacted only while it
    // is registered.
    #[cfg(feature = "test-commands")]
    let _held;
    #[cfg(feature = "test-commands")]
    let result = if let Command::TestConsole { mode } = cli.subcommand() {
        match rotate::secret::SecretValue::from_reader(std::io::stdin().lock()) {
            Ok(secret) => {
                _held = secret;
                test_console(&mut console, mode, &_held)
            }
            Err(err) => Err(err.into()),
        }
    } else {
        run(&mut console, cli.subcommand(), &config, cli.global.json)
    };
    #[cfg(not(feature = "test-commands"))]
    let result = run(&mut console, cli.subcommand(), &config, cli.global.json);
    // Writes the mock call log when a test scenario asks for it; a no-op in
    // release builds (SHA-250).
    providers::finish();
    match result {
        Ok(exit) => exit.into(),
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            Exit::RotationFailed.into()
        }
    }
}

/// Sends tracing events to stderr through the redaction layer (SHA-218), at
/// the level the `-v` count selects. Installing can only fail if a
/// subscriber is already set, which nothing in this binary does.
fn install_logging(verbose: u8) {
    let level = rotate::redact::level_for(verbose);
    let _ =
        tracing::subscriber::set_global_default(rotate::redact::subscriber(level, std::io::stderr));
}

/// Runs one subcommand. Errors are printed, redacted, by `main` with exit 1.
fn run(
    console: &mut Console,
    command: Command,
    config: &Config,
    json: bool,
) -> Result<Exit, rotate::error::Error> {
    if let Some(input) = command.input() {
        let findings = match read_input(console, input) {
            Ok(findings) => findings,
            Err(exit) => return Ok(exit),
        };
        if let Command::Plan(_) = command {
            return Ok(plan(console, findings, input, config, json));
        }
    }
    // Still stubs until their tickets land (SHA-254 apply, SHA-259
    // rollback, SHA-263 status).
    let _ = writeln!(console.err(), "rotate {}: not implemented", command.name());
    Ok(Exit::Usage)
}

/// Builds the plan (SHA-250) and prints the table or JSON: assessment
/// (SHA-248), then `find` on every consumer, then a `planned` record per new
/// rotation in the state file. No state-changing remote call is made.
/// Blockers and skipped rows are information, not failures: exit 0. A held
/// or unusable state file exits 2 before any provider call; a plain I/O
/// error writing it exits 1.
fn plan(
    console: &mut Console,
    findings: Vec<Finding>,
    input: &InputArgs,
    config: &Config,
    json: bool,
) -> Exit {
    let mut store = match StateStore::open(&config.state_file) {
        Ok(store) => store,
        Err(err) => return state_error(console, err),
    };
    let registry = providers::registry();
    let consumers = providers::consumers(config);
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
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = writeln!(
                console.err(),
                "error: could not start the async runtime: {err}"
            );
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
        return state_error(console, err);
    }
    drop(store);
    let rendered = if json {
        plan::render_json(&plan) + "\n"
    } else {
        plan::render_table(&plan)
    };
    print_out(console, &rendered);
    Exit::Ok
}

/// Reports a state-store error: exit 2 for a held lock or an unusable file
/// (the operator must act), exit 1 for a plain I/O failure.
fn state_error(console: &mut Console, err: StateError) -> Exit {
    let _ = writeln!(console.err(), "error: {err}");
    if err.is_usage() {
        Exit::Usage
    } else {
        Exit::RotationFailed
    }
}

/// The single stdout print site for command output (plan table or JSON):
/// one redacted write of the whole rendering.
fn print_out(console: &mut Console, text: &str) {
    let _ = console.out().write_all(text.as_bytes());
}

/// Reads the findings named by `input` (SHA-247). Errors are printed here
/// and never include what was read or a path the operator typed: a secret
/// pasted where the report path goes must not be echoed back.
fn read_input(console: &mut Console, input: &InputArgs) -> Result<Vec<Finding>, Exit> {
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
            let _ = writeln!(
                console.err(),
                "error: unknown provider; known providers: {known}"
            );
            return Err(Exit::Usage);
        }
    }

    if input.stdin {
        let stdin = std::io::stdin();
        // The hint is best effort; a closed stderr must not stop the read.
        let _ = rotate::input::stdin_hint(stdin.is_terminal(), &mut console.err());
        return match rotate::input::read_secret(stdin.lock()) {
            Ok(finding) => Ok(vec![finding]),
            Err(err) => {
                let _ = writeln!(console.err(), "error: {err}");
                Err(Exit::Usage)
            }
        };
    }

    let Some(path) = &input.report else {
        let _ = writeln!(
            console.err(),
            "error: no input: pass a report path or --stdin"
        );
        return Err(Exit::Usage);
    };
    match read_report(path, input.format) {
        Ok(report) => {
            for warning in &report.warnings {
                let _ = writeln!(console.err(), "warning: {warning}");
            }
            Ok(report.findings)
        }
        Err(ReportError::Io { source, .. }) => {
            let usage = Cli::command().render_usage();
            let _ = writeln!(
                console.err(),
                "error: could not read the report file ({}). Secrets must be passed with --stdin, never as an argument.\n\n{usage}",
                source.kind()
            );
            Err(Exit::Usage)
        }
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            Err(Exit::Usage)
        }
    }
}

/// The hidden `__test-console` subcommand (`test-commands` feature only).
/// `secret` was read from stdin, so it is registered with the redactor as
/// real input is. It goes down the output path `mode` names, and is also
/// logged at error level so tests can check the tracing path.
#[cfg(feature = "test-commands")]
fn test_console(
    console: &mut Console,
    mode: cli::TestConsoleMode,
    secret: &rotate::secret::SecretValue,
) -> Result<Exit, rotate::error::Error> {
    use cli::TestConsoleMode;
    use rotate::provider::ProviderError;

    let value = secret
        .expose_secret_str(str::to_owned)
        .map_err(rotate::error::Error::new)?;
    tracing::error!("test-console saw {value}");
    match mode {
        TestConsoleMode::Out => {
            let _ = writeln!(console.out(), "value: {value}");
            Ok(Exit::Ok)
        }
        TestConsoleMode::Error => {
            Err(ProviderError::Permanent(format!("provider rejected {value}")).into())
        }
        TestConsoleMode::Panic => panic!("test-console panic with {value}"),
        TestConsoleMode::Json => {
            let doc = serde_json::json!({
                "rotations": [{
                    "fingerprint": secret.fingerprint().to_string(),
                    "note": format!("upstream echoed {value}"),
                    "values": [value.clone(), { "nested": value }],
                }],
            });
            print_out(console, &(doc.to_string() + "\n"));
            Ok(Exit::Ok)
        }
    }
}
