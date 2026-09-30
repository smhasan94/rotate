//! `rotate` entry point.
//!
//! This is the only file allowed to write directly to stdout or stderr until
//! the redacted console (SHA-246) exists.

mod cli;
mod exit;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::exit::Exit;

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli.subcommand()).into()
}

fn run(command: Command) -> Exit {
    // Every subcommand is a stub until its ticket lands (SHA-250 plan,
    // SHA-254 apply, SHA-259 rollback, SHA-263 status).
    eprintln!("rotate {}: not implemented", command.name());
    Exit::Usage
}
