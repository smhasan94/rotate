//! `rotate` entry point.
//!
//! This is the only file allowed to write directly to stdout or stderr until
//! the redacted console (SHA-246) exists.

mod cli;
mod exit;

use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};

use rotate::config::Config;

use crate::cli::{Cli, Command};
use crate::exit::Exit;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return handle_parse_error(err),
    };
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
    // Every subcommand is a stub until its ticket lands (SHA-250 plan,
    // SHA-254 apply, SHA-259 rollback, SHA-263 status).
    eprintln!("rotate {}: not implemented", command.name());
    Exit::Usage
}
