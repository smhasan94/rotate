//! Process exit codes shared by every subcommand.
//!
//! The values are part of the CLI contract and are documented for
//! non-interactive callers such as a future GitHub Action.

use std::process::ExitCode;

/// Exit status of a `rotate` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Exit {
    /// Everything requested was done.
    Ok = 0,
    /// A rotation step failed. The old secret is still valid unless the
    /// output says otherwise.
    RotationFailed = 1,
    /// Bad arguments, bad configuration, or a subcommand that is not
    /// implemented yet.
    Usage = 2,
    /// Work is pending, for example a revoke waiting for its overlap window.
    Pending = 3,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        ExitCode::from(exit as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_contract() {
        assert_eq!(Exit::Ok as u8, 0);
        assert_eq!(Exit::RotationFailed as u8, 1);
        assert_eq!(Exit::Usage as u8, 2);
        assert_eq!(Exit::Pending as u8, 3);
    }
}
