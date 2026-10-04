//! Library half of `rotate`: the types the binary and its tests share.
//!
//! The binary in `main.rs` keeps the CLI and exit-code modules private for
//! now; this crate root grows one module per core ticket. `unsafe` is denied
//! crate-wide and allowed only in tests that need to inspect raw memory.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod apply;
pub mod assess;
pub mod audit;
pub mod calls;
pub mod config;
pub mod conformance;
pub mod console;
pub mod consumer;
pub mod error;
pub mod finding;
pub mod fsutil;
pub mod github;
pub mod input;
pub mod plan;
pub mod provider;
pub mod redact;
pub mod report;
pub mod rollback;
pub mod secret;
pub mod state;
pub mod status;
