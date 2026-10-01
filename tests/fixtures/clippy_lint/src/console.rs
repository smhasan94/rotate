//! Mirrors the exemption a console module may use: no lint here.
#![allow(clippy::disallowed_macros)]

/// Allowed print.
pub fn allowed() {
    println!("allowed");
}
