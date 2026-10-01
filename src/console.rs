//! The only way `rotate` writes to stdout and stderr (SHA-246, NFR2).
//!
//! [`Console::out`] and [`Console::err`] return a writer that buffers one
//! message and writes [`redact`] of it when dropped, so every byte the binary
//! prints passes the same redaction as the logs. Use one guard per message,
//! with `write!` or `writeln!`:
//!
//! ```
//! use std::io::Write;
//! let mut console = rotate::console::Console::new(Vec::new(), Vec::new());
//! let _ = writeln!(console.out(), "rotated {} keys", 2);
//! let (out, _) = console.into_inner();
//! assert_eq!(out, b"rotated 2 keys\n");
//! ```
//!
//! `println!`, `eprintln!`, `print!`, `eprint!` and `dbg!` are disallowed by
//! `clippy.toml` everywhere else. This module does not need them either.
//!
//! The module also holds the two other output paths that bypass the
//! console: clap's parse errors ([`Console::report_parse_error`]) and the
//! panic hook ([`install_panic_hook`]).

use std::cell::Cell;
use std::fmt::{self, Write as _};
use std::io::{self, Stderr, Stdout, Write};

use clap::error::{ContextKind, ContextValue, ErrorKind};
use zeroize::Zeroizing;

use crate::redact::{redact, RedactingWriter};

/// Shown wherever a typed value is left out of an error.
const STDIN_HINT: &str = "Secrets must be passed with --stdin, never as an argument.";

/// Redacted stdout and stderr.
#[derive(Debug)]
pub struct Console<O: Write = Stdout, E: Write = Stderr> {
    out: O,
    err: E,
}

impl Console {
    /// The process's real stdout and stderr.
    pub fn stdio() -> Self {
        Self::new(io::stdout(), io::stderr())
    }
}

impl<O: Write, E: Write> Console<O, E> {
    /// A console over any two writers (tests use `Vec<u8>`).
    pub fn new(out: O, err: E) -> Self {
        Self { out, err }
    }

    /// A writer for one stdout message. Nothing is written until it drops.
    pub fn out(&mut self) -> RedactingWriter<&mut O> {
        RedactingWriter::new(&mut self.out)
    }

    /// A writer for one stderr message. Nothing is written until it drops.
    pub fn err(&mut self) -> RedactingWriter<&mut E> {
        RedactingWriter::new(&mut self.err)
    }

    /// The two writers back.
    pub fn into_inner(self) -> (O, E) {
        (self.out, self.err)
    }

    /// Prints a clap parse error and returns clap's exit code (0 for help
    /// and version, 2 otherwise).
    ///
    /// clap repeats the offending value in several error kinds. An operator
    /// who pastes a secret as an argument instead of using `--stdin` would
    /// get it echoed, and nothing is registered with the redactor yet at
    /// parse time, so those kinds get a message without the value. Every
    /// other kind prints clap's own text, redacted. `usage` is the rendered
    /// usage line.
    pub fn report_parse_error(&mut self, err: &clap::Error, usage: &dyn fmt::Display) -> i32 {
        let text = Zeroizing::new(match err.kind() {
            ErrorKind::InvalidSubcommand | ErrorKind::UnknownArgument | ErrorKind::TooManyValues => {
                format!(
                    "error: unrecognized argument. {STDIN_HINT}\n\n{usage}\n\nFor more information, try '--help'.\n"
                )
            }
            ErrorKind::InvalidValue
            | ErrorKind::ValueValidation
            | ErrorKind::WrongNumberOfValues
            | ErrorKind::InvalidUtf8
            | ErrorKind::NoEquals => {
                let arg = match err.get(ContextKind::InvalidArg) {
                    Some(ContextValue::String(arg)) => format!(" for '{arg}'"),
                    _ => String::new(),
                };
                format!(
                    "error: invalid value{arg} (the value is not shown). {STDIN_HINT}\n\n{usage}\n\nFor more information, try '--help'.\n"
                )
            }
            _ => err.render().to_string(),
        });
        let _ = if err.use_stderr() {
            self.err().write_all(text.as_bytes())
        } else {
            self.out().write_all(text.as_bytes())
        };
        err.exit_code()
    }
}

thread_local! {
    /// Set while this thread is inside the panic hook.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

/// Replaces the default panic hook with one that redacts the payload and
/// location before writing them to stderr.
///
/// The process still unwinds out of `main`, so a panic on the main thread
/// exits with 101 as before. Backtraces are not printed. If `redact` itself
/// panicked inside the hook, std aborts without calling the hook again and
/// without printing that payload; the thread-local guard is a second line
/// of defence that prints a fixed line instead of recursing.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let location = info.location().map(ToString::to_string);
        let payload = info.payload_as_str().unwrap_or("Box<dyn Any>");
        report_panic(
            &mut io::stderr().lock(),
            thread.name().unwrap_or("<unnamed>"),
            location.as_deref(),
            payload,
        );
    }));
}

/// Writes one redacted panic report to `w`. Write errors are ignored: there
/// is nowhere else to report them.
fn report_panic(w: &mut dyn Write, thread: &str, location: Option<&str>, payload: &str) {
    if IN_HOOK.with(|flag| flag.replace(true)) {
        let _ = w.write_all(b"rotate panicked while reporting a panic\n");
        return;
    }
    let mut text = Zeroizing::new(String::with_capacity(payload.len() + 64));
    let _ = write!(text, "thread '{thread}' panicked");
    if let Some(location) = location {
        let _ = write!(text, " at {location}");
    }
    let _ = write!(text, ":\n{payload}\n");
    let redacted = Zeroizing::new(redact(&text).into_owned());
    let _ = w.write_all(redacted.as_bytes());
    let _ = w.flush();
    IN_HOOK.with(|flag| flag.set(false));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;

    fn marker(secret: &SecretValue) -> String {
        format!("[REDACTED {}]", secret.fingerprint())
    }

    // T1 (AC1)
    #[test]
    fn out_redacts_registered_value() {
        let canary = ["console-out-canary-", "1c7e40aa"].concat();
        let secret = SecretValue::from(canary.as_str());
        let mut console = Console::new(Vec::new(), Vec::new());
        writeln!(console.out(), "token: {canary}").unwrap();
        let (out, err) = console.into_inner();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out, format!("token: {}\n", marker(&secret)));
        assert!(err.is_empty());
    }

    // T1 (AC1), stderr half
    #[test]
    fn err_redacts_registered_value() {
        let canary = ["console-err-canary-", "93bd0f51"].concat();
        let secret = SecretValue::from(canary.as_str());
        let mut console = Console::new(Vec::new(), Vec::new());
        {
            // A value split across writes in one guard is caught whole.
            let mut w = console.err();
            w.write_all(b"error: ").unwrap();
            w.write_all(&canary.as_bytes()[..6]).unwrap();
            w.write_all(&canary.as_bytes()[6..]).unwrap();
            w.write_all(b"\n").unwrap();
        }
        let (out, err) = console.into_inner();
        let err = String::from_utf8(err).unwrap();
        assert!(out.is_empty());
        assert_eq!(err, format!("error: {}\n", marker(&secret)));
    }

    // T5 unit half (AC5)
    #[test]
    fn json_through_console_stays_valid() {
        let canary = ["console-json-", "\"quoted\"-5a0e"].concat();
        let secret = SecretValue::from(canary.as_str());
        let doc = serde_json::json!({ "note": format!("saw {canary}"), "list": [canary] });
        for text in [doc.to_string(), serde_json::to_string_pretty(&doc).unwrap()] {
            let mut console = Console::new(Vec::new(), Vec::new());
            writeln!(console.out(), "{text}").unwrap();
            let (out, _) = console.into_inner();
            let out = String::from_utf8(out).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["note"], format!("saw {}", marker(&secret)));
            assert_eq!(parsed["list"][0], marker(&secret));
            assert!(!out.contains("console-json-"), "{out}");
        }
    }

    // T3 unit half (AC3)
    #[test]
    fn panic_report_is_redacted() {
        let canary = ["console-panic-", "c0ffee42"].concat();
        let secret = SecretValue::from(canary.as_str());
        let mut buf = Vec::new();
        report_panic(&mut buf, "main", Some("src/x.rs:1:2"), &format!("boom {canary}"));
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(
            text,
            format!(
                "thread 'main' panicked at src/x.rs:1:2:\nboom {}\n",
                marker(&secret)
            )
        );
        // The guard is cleared afterwards.
        assert!(!IN_HOOK.with(Cell::get));
    }

    #[test]
    fn reentered_hook_prints_fixed_line() {
        let canary = ["console-reenter-", "0d15ea5e"].concat();
        let _secret = SecretValue::from(canary.as_str());
        IN_HOOK.with(|flag| flag.set(true));
        let mut buf = Vec::new();
        report_panic(&mut buf, "main", None, &canary);
        IN_HOOK.with(|flag| flag.set(false));
        assert_eq!(buf, b"rotate panicked while reporting a panic\n");
    }

    fn parse_error(args: &[&str]) -> (i32, String, String) {
        use clap::{Arg, Command};
        let cmd = Command::new("t")
            .arg(
                Arg::new("n")
                    .long("n")
                    .value_parser(clap::value_parser!(u8)),
            )
            .arg(Arg::new("mode").long("mode").value_parser(["a", "b"]));
        let err = cmd.try_get_matches_from(args).unwrap_err();
        let mut console = Console::new(Vec::new(), Vec::new());
        let code = console.report_parse_error(&err, &"Usage: t [OPTIONS]");
        let (out, errs) = console.into_inner();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(errs).unwrap(),
        )
    }

    #[test]
    fn parse_errors_never_echo_values() {
        let canary = ["parse-canary-", "a1b2c3d4"].concat();
        for args in [
            vec!["t", canary.as_str()],
            vec!["t", "--nope", canary.as_str()],
            vec!["t", "--n", canary.as_str()],
            vec!["t", "--mode", canary.as_str()],
        ] {
            let (code, out, err) = parse_error(&args);
            assert_eq!(code, 2, "{args:?}");
            assert!(out.is_empty());
            assert!(!err.contains(&canary), "{err}");
            assert!(err.contains(STDIN_HINT), "{err}");
            assert!(err.contains("Usage: t"), "{err}");
        }
        let (_, _, err) = parse_error(&["t", "--n", canary.as_str()]);
        assert!(err.contains("invalid value for '--n <n>'"), "{err}");
    }

    #[test]
    fn help_goes_to_stdout_with_code_0() {
        let (code, out, err) = parse_error(&["t", "--help"]);
        assert_eq!(code, 0);
        assert!(out.contains("Usage: t"), "{out}");
        assert!(err.is_empty());
    }
}
