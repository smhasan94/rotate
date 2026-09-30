//! Sample live test (SHA-216 T3 and T4). Runs only with
//! `ROTATE_LIVE_TESTS=1 cargo test -- --ignored live_`.

mod common;

use common::{live_guard, require_env};

#[test]
#[ignore]
fn live_smoke() {
    live_guard!();
    assert_eq!(require_env("ROTATE_LIVE_TESTS").as_deref(), Some("1"));
}
