//! Prints outside the console module: the lint must fire here.

mod console;

/// Prints without redaction.
pub fn leak(value: &str) {
    println!("{value}");
}

/// Keeps the console module used.
pub fn quiet() {
    console::allowed();
}
