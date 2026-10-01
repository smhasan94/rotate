//! Library half of `rotate`: the types the binary and its tests share.
//!
//! The binary in `main.rs` keeps the CLI and exit-code modules private for
//! now; this crate root grows one module per core ticket. `unsafe` is denied
//! crate-wide and allowed only in tests that need to inspect raw memory.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod calls;
pub mod finding;
pub mod provider;
pub mod report;
pub mod secret;
