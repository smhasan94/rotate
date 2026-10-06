//! SHA-339 T1 (AC1): `scripts/render-formula.sh` renders the Homebrew
//! formula from a version and a `SHA256SUMS` file.
//!
//! The fixture `packaging/homebrew/fixtures/SHA256SUMS` holds made-up
//! checksums for version 1.2.3, and `fixtures/rotate.rb` is the formula
//! they must render to. The same fixture is what `brew audit --strict` and
//! `brew style` check in `.github/workflows/homebrew.yml` (T2).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(ROOT)
        .join("packaging/homebrew/fixtures")
        .join(name)
}

fn render(version: &str, sums: &Path) -> Output {
    Command::new("bash")
        .arg(Path::new(ROOT).join("scripts/render-formula.sh"))
        .arg(version)
        .arg(sums)
        .output()
        .expect("run bash")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// `(checksum, file name)` for every line of the fixture.
fn fixture_lines() -> Vec<(String, String)> {
    std::fs::read_to_string(fixture("SHA256SUMS"))
        .unwrap()
        .lines()
        .map(|line| {
            let (sum, name) = line.split_once("  ").unwrap();
            (sum.to_owned(), name.to_owned())
        })
        .collect()
}

/// A `SHA256SUMS` in a temp dir with `body` as its contents.
fn sums_file(body: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("SHA256SUMS");
    std::fs::write(&path, body).unwrap();
    (dir, path)
}

fn assert_fails(output: &Output) -> String {
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "render succeeded:\n{stderr}");
    assert!(
        output.stdout.is_empty(),
        "a failed render printed a formula"
    );
    stderr
}

#[test]
fn sha339_t1_renders_the_fixture() {
    let output = render("1.2.3", &fixture("SHA256SUMS"));
    assert!(output.status.success(), "{}", text(&output.stderr));
    let formula = text(&output.stdout);
    let expected = std::fs::read_to_string(fixture("rotate.rb")).unwrap();
    assert_eq!(formula, expected);

    // Every target's URL for this version, followed by its own checksum.
    let lines = fixture_lines();
    for target in TARGETS {
        let name = format!("rotate-1.2.3-{target}.tar.gz");
        let url =
            format!("url \"https://github.com/smhasan94/rotate/releases/download/v1.2.3/{name}\"");
        let (sum, _) = lines.iter().find(|(_, n)| *n == name).unwrap();
        let at = formula.find(&url).unwrap_or_else(|| panic!("no {url}"));
        let next = formula[at..].lines().nth(1).unwrap().trim();
        assert_eq!(next, format!("sha256 \"{sum}\""), "{target}");
    }
    assert!(!formula.contains('@'), "placeholder left:\n{formula}");
    assert!(formula.contains("bin.install \"rotate\""));
    assert!(formula.contains("rotate --version"));

    // A leading `v` and `*` binary markers are accepted.
    let starred: String = lines
        .iter()
        .map(|(sum, name)| format!("{sum} *{name}\n"))
        .collect();
    let (_dir, path) = sums_file(&starred);
    let output = render("v1.2.3", &path);
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), expected);
}

#[test]
fn sha339_t1_missing_target_fails_naming_it() {
    let lines = fixture_lines();
    for target in TARGETS {
        let body: String = lines
            .iter()
            .filter(|(_, name)| !name.contains(target))
            .map(|(sum, name)| format!("{sum}  {name}\n"))
            .collect();
        let (_dir, path) = sums_file(&body);
        let stderr = assert_fails(&render("1.2.3", &path));
        assert!(
            stderr.contains(&format!("missing target {target}")),
            "{target}: {stderr}"
        );
        for other in TARGETS.iter().filter(|t| **t != target) {
            assert!(
                !stderr.contains(&format!("missing target {other}:")),
                "{other} named for {target}: {stderr}"
            );
        }
    }
}

#[test]
fn sha339_t1_wrong_version_names_every_target() {
    let stderr = assert_fails(&render("1.2.4", &fixture("SHA256SUMS")));
    for target in TARGETS {
        assert!(
            stderr.contains(&format!(
                "missing target {target}: SHA256SUMS has no line for rotate-1.2.4-{target}.tar.gz"
            )),
            "{target}: {stderr}"
        );
    }
}

#[test]
fn sha339_t1_rejects_bad_checksum_and_version() {
    let lines = fixture_lines();

    // A checksum that is not 64 lowercase hex digits.
    let body: String = lines
        .iter()
        .map(|(sum, name)| {
            let sum = if name.contains("x86_64-apple-darwin") {
                sum.to_uppercase()
            } else {
                sum.clone()
            };
            format!("{sum}  {name}\n")
        })
        .collect();
    let (_dir, path) = sums_file(&body);
    let stderr = assert_fails(&render("1.2.3", &path));
    assert!(stderr.contains("target x86_64-apple-darwin"), "{stderr}");

    // The same tarball listed twice.
    let mut body: String = lines
        .iter()
        .map(|(sum, name)| format!("{sum}  {name}\n"))
        .collect();
    body.push_str(&format!("{}  {}\n", lines[0].0, lines[0].1));
    let (_dir, path) = sums_file(&body);
    let stderr = assert_fails(&render("1.2.3", &path));
    assert!(stderr.contains("2 lines"), "{stderr}");

    // Versions that are not X.Y.Z, including ones sed would misread.
    for version in ["1.2", "latest", "1.2.3/x", "1.2.3&", ""] {
        let stderr = assert_fails(&render(version, &fixture("SHA256SUMS")));
        assert!(stderr.contains("is not X.Y.Z"), "{version:?}: {stderr}");
    }

    // A missing file.
    let stderr = assert_fails(&render("1.2.3", Path::new("/nonexistent/SHA256SUMS")));
    assert!(stderr.contains("no such file"), "{stderr}");
}
