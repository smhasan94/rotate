//! SHA-223 T4 and T7: skipped report lines are reported by number only, and
//! no fixture secret reaches a warning, `Debug` output or tracing.

mod common;

use rotate::report::{parse_report, read_report, ParsedReport};

const TRUFFLEHOG: &[u8] = include_bytes!("fixtures/trufflehog.ndjson");
const TRUFFLEHOG_AWS_LEGACY: &[u8] = include_bytes!("fixtures/trufflehog_aws_legacy.ndjson");
const TRUFFLEHOG_MALFORMED: &[u8] = include_bytes!("fixtures/trufflehog_malformed.ndjson");
const GITLEAKS: &[u8] = include_bytes!("fixtures/gitleaks.json");

/// Every secret value in the fixtures, including the garbage on line 2 of
/// the malformed fixture.
const SECRETS: &[&str] = &[
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001",
    "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002",
    "CANARYgarbageLineTwoMustNotPrint",
];

fn rendered(report: &ParsedReport) -> String {
    let warnings: Vec<String> = report.warnings.iter().map(ToString::to_string).collect();
    format!("{report:?} {report:#?} {}", warnings.join(" "))
}

// T4 (AC4)
#[test]
fn malformed_line_is_skipped_with_line_number() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let report = parse_report(TRUFFLEHOG_MALFORMED, None).unwrap();

    let detectors: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.detector.as_str())
        .collect();
    assert_eq!(detectors, ["Github", "NpmToken"]);
    assert_eq!(report.warnings.len(), 1);
    let warning = report.warnings[0].to_string();
    assert!(warning.contains("line 2"), "{warning}");

    let logs = capture.contents();
    assert!(logs.contains("line 2"), "warning not logged");
    // Failure messages name the channel only: printing it would print the leak.
    for (label, text) in [("warning", &warning), ("tracing", &logs)] {
        assert!(!text.contains("CANARYgarbage"), "{label}: garbage leaked");
        assert!(!text.contains("ghp_"), "{label}: garbage leaked");
    }
}

// T7 (AC1, AC2, AC4)
#[test]
fn parsed_reports_never_render_secrets() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let dirs = common::TestDirs::new();
    let on_disk = dirs.path().join("gitleaks.json");
    std::fs::write(&on_disk, GITLEAKS).unwrap();

    let reports = [
        parse_report(TRUFFLEHOG, None).unwrap(),
        parse_report(TRUFFLEHOG_AWS_LEGACY, None).unwrap(),
        parse_report(TRUFFLEHOG_MALFORMED, None).unwrap(),
        parse_report(GITLEAKS, None).unwrap(),
        read_report(&on_disk, None).unwrap(),
    ];
    for report in &reports {
        tracing::info!(?report, "parsed");
    }
    let finding_count: usize = reports.iter().map(|r| r.findings.len()).sum();
    assert_eq!(finding_count, 3 + 1 + 2 + 3 + 3);

    let rendered: String = reports.iter().map(rendered).collect();
    let logs = capture.contents();
    assert!(logs.contains("parsed"), "event not captured");
    for (label, text) in [("debug output", &rendered), ("tracing", &logs)] {
        for (index, secret) in SECRETS.iter().enumerate() {
            assert!(!text.contains(secret), "{label}: SECRETS[{index}] leaked");
        }
        for fingerprint in reports
            .iter()
            .flat_map(|r| &r.findings)
            .map(|f| f.fingerprint())
        {
            assert!(
                text.contains(fingerprint.as_str()),
                "{label}: {fingerprint} missing"
            );
        }
    }
}
