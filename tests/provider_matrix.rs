//! SHA-266: `docs/providers.md` stays in step with the code.
//!
//! T1 parses the doc's tables and checks every registered provider and
//! consumer has a row per operation with a status and a note, and that
//! every method of the `Provider` and `Consumer` traits is named in the
//! doc. T2 builds each real provider with no operator credential and
//! derives as many cells as it can from the provider itself, with no
//! network call except a local wiremock for AWS `restore`, then compares
//! them with the doc.
//!
//! Test values are built at runtime and shaped so no secret scanner
//! matches them.

use std::collections::BTreeMap;

use aws_sdk_sts::config::Credentials;
use wiremock::matchers::body_string_contains;
use wiremock::{Mock, MockServer, ResponseTemplate};

use rotate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use rotate::provider::aws::AwsProvider;
use rotate::provider::github::GithubProvider;
use rotate::provider::npm::NpmProvider;
use rotate::provider::openai::{AdminKey, OpenAiProvider};
use rotate::provider::{Identity, Provider, ProviderError, ReplacementMode, RestoreOutcome};
use rotate::secret::SecretValue;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Rows every provider table has: the seven operations SHA-266 names plus
/// the resume (SHA-258) and rollback (SHA-259) ones.
const PROVIDER_OPS: [&str; 9] = [
    "identify",
    "check_valid",
    "describe_scope",
    "create_replacement",
    "verify",
    "verify_replacement",
    "revoke",
    "revoke_replacement",
    "restore",
];

/// Rows every consumer table has.
const CONSUMER_OPS: [&str; 3] = ["find", "update", "restore"];

/// The registered plugins, by the names the CLI registers them under.
const PROVIDERS: [&str; 4] = [
    rotate::provider::aws::NAME,
    rotate::provider::github::NAME,
    rotate::provider::npm::NAME,
    rotate::provider::openai::NAME,
];
const CONSUMERS: [&str; 2] = [
    rotate::consumer::github_actions::NAME,
    rotate::consumer::aws_secrets_manager::NAME,
];

/// The suffix of a status that depends on the OpenAI admin key.
const WITHOUT_ADMIN: &str = " without admin key";

/// The suffix of a status that also depends on the OpenAI opt-in to a
/// broader replacement (SHA-291).
const WITHOUT_ADMIN_OR_OPT_IN: &str = " without admin key or opt-in";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Automated,
    Manual,
    Unsupported,
}

impl Status {
    fn parse(text: &str) -> Status {
        match text.trim() {
            "Automated" => Status::Automated,
            "Manual" => Status::Manual,
            "Unsupported" => Status::Unsupported,
            other => panic!("unknown status {other:?}"),
        }
    }
}

/// A status cell: `Automated`, or `Automated; Manual without admin key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cell {
    /// With the operator credential set.
    with: Status,
    /// Without it, when that differs.
    without: Status,
}

impl Cell {
    fn parse(text: &str) -> Cell {
        match text.split_once(';') {
            None => {
                let status = Status::parse(text);
                Cell {
                    with: status,
                    without: status,
                }
            }
            Some((with, without)) => {
                let without = without.trim();
                let without = without
                    .strip_suffix(WITHOUT_ADMIN_OR_OPT_IN)
                    .or_else(|| without.strip_suffix(WITHOUT_ADMIN))
                    .unwrap_or_else(|| panic!("{text:?}: expected \"<status>{WITHOUT_ADMIN}\""));
                Cell {
                    with: Status::parse(with),
                    without: Status::parse(without),
                }
            }
        }
    }
}

struct Row {
    cell: Cell,
    credential: String,
    note: String,
}

/// `## Providers` or `## Consumers`, then plugin name, then operation.
type Tables = BTreeMap<String, BTreeMap<String, BTreeMap<String, Row>>>;

fn doc() -> String {
    std::fs::read_to_string(format!("{ROOT}/docs/providers.md")).expect("read docs/providers.md")
}

/// Every `### Title (`name`)` table under `## Providers` and
/// `## Consumers`.
fn tables(doc: &str) -> Tables {
    let mut tables = Tables::new();
    let mut part: Option<String> = None;
    let mut plugin: Option<String> = None;
    for line in doc.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            part = matches!(heading, "Providers" | "Consumers").then(|| heading.to_owned());
            plugin = None;
            continue;
        }
        if let Some(heading) = line.strip_prefix("### ") {
            plugin = heading
                .rsplit_once("(`")
                .and_then(|(_, rest)| rest.strip_suffix("`)"))
                .map(str::to_owned);
            continue;
        }
        let (Some(part), Some(plugin)) = (&part, &plugin) else {
            continue;
        };
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let cells: Vec<&str> = rest
            .trim_end_matches('|')
            .split(" | ")
            .map(str::trim)
            .collect();
        assert_eq!(cells.len(), 4, "{plugin}: a row needs 4 columns: {line}");
        let op = cells[0].trim_end_matches('`').to_owned();
        let row = Row {
            cell: Cell::parse(cells[1]),
            credential: cells[2].to_owned(),
            note: cells[3].to_owned(),
        };
        let previous = tables
            .entry(part.clone())
            .or_default()
            .entry(plugin.clone())
            .or_default()
            .insert(op.clone(), row);
        assert!(previous.is_none(), "{plugin}: {op} appears twice");
    }
    tables
}

/// Method names declared in `pub trait <name>` in `src/<file>`.
fn trait_methods(file: &str, name: &str) -> Vec<String> {
    let source = std::fs::read_to_string(format!("{ROOT}/src/{file}")).unwrap();
    let start = source
        .find(&format!("pub trait {name}"))
        .unwrap_or_else(|| panic!("no trait {name} in {file}"));
    let body = &source[start..];
    let end = body.find("\n}\n").expect("end of trait");
    body[..end]
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let l = l.strip_prefix("async ").unwrap_or(l);
            let rest = l.strip_prefix("fn ")?;
            Some(rest.split(['(', '<']).next()?.to_owned())
        })
        .collect()
}

// T1 (AC1): 4 providers x 9 operations and 2 consumers x 3 operations,
// each with a status and a note.
#[test]
fn every_plugin_has_every_operation_with_status_and_note() {
    let tables = tables(&doc());
    let providers = &tables["Providers"];
    let consumers = &tables["Consumers"];
    assert_eq!(
        providers.keys().map(String::as_str).collect::<Vec<_>>(),
        sorted(&PROVIDERS)
    );
    assert_eq!(
        consumers.keys().map(String::as_str).collect::<Vec<_>>(),
        sorted(&CONSUMERS)
    );
    for (plugin, rows) in providers {
        assert_eq!(
            rows.keys().map(String::as_str).collect::<Vec<_>>(),
            sorted(&PROVIDER_OPS),
            "{plugin}"
        );
    }
    for (plugin, rows) in consumers {
        assert_eq!(
            rows.keys().map(String::as_str).collect::<Vec<_>>(),
            sorted(&CONSUMER_OPS),
            "{plugin}"
        );
        let find = &rows["find"].note;
        assert!(
            find.starts_with("ByValue") || find.starts_with("ByName"),
            "{plugin}: the find note must start with ByValue or ByName: {find}"
        );
    }
    for (plugin, rows) in providers.iter().chain(consumers) {
        for (op, row) in rows {
            assert!(row.note.len() > 10, "{plugin} {op}: note missing");
            assert!(!row.credential.is_empty(), "{plugin} {op}: credential");
        }
    }
}

fn sorted<'a>(names: &[&'a str]) -> Vec<&'a str> {
    let mut names = names.to_vec();
    names.sort_unstable();
    names
}

// T1 (AC1): a new trait method fails this test until the doc names it.
#[test]
fn every_trait_method_is_named_in_the_doc() {
    let doc = doc();
    let provider = trait_methods("provider/mod.rs", "Provider");
    let consumer = trait_methods("consumer/mod.rs", "Consumer");
    assert!(provider.len() >= 12, "{provider:?}");
    assert!(consumer.len() >= 4, "{consumer:?}");
    for method in provider.iter().chain(&consumer) {
        assert!(
            doc.contains(&format!("`{method}`")),
            "docs/providers.md does not name trait method `{method}`"
        );
    }
}

/// `len` letters and digits, built at runtime.
fn filler(len: usize) -> String {
    "Ab3".chars().cycle().take(len).collect()
}

/// A finding in the provider's format, for `identify`.
fn sample(provider: &str) -> Finding {
    let source = SourceLocation::file("matrix.env");
    match provider {
        "aws" => {
            let key_id = ["AK", "IA", "MATRIXTESTKEY001"].concat();
            Finding::new(SecretValue::from(filler(40)), "AWS", source)
                .with_extra(ACCESS_KEY_ID, key_id)
        }
        "github" => Finding::new(
            SecretValue::from(["gh", "p_", &filler(36)].concat()),
            "Github",
            source,
        ),
        "npm" => Finding::new(
            SecretValue::from(["np", "m_", &filler(36)].concat()),
            "NpmToken",
            source,
        ),
        "openai" => Finding::new(
            SecretValue::from(["sk", "-proj-", &filler(40)].concat()),
            "OpenAI",
            source,
        ),
        other => panic!("no sample for {other}"),
    }
}

/// True when `result` is `Unsupported`, as the trait defaults answer.
fn unsupported<T>(result: &Result<T, ProviderError>) -> bool {
    matches!(result, Err(ProviderError::Unsupported(_)))
}

/// The cells T2 can derive from `provider` without a network call.
/// `restore` is added by the caller.
async fn derive(provider: &dyn Provider) -> BTreeMap<&'static str, Status> {
    let name = provider.name();
    let finding = sample(name);
    let credential = finding.credential();
    let identity = Identity("matrix-identity".into());
    let mode = provider.replacement_mode();
    let mut cells = BTreeMap::new();

    cells.insert(
        "identify",
        match provider.identify(&finding) {
            Some(_) => Status::Automated,
            None => Status::Unsupported,
        },
    );

    let create = match mode {
        ReplacementMode::Automatic => Status::Automated,
        ReplacementMode::Manual => {
            // Manual mode never calls it; when it is called it refuses
            // before any request.
            let result = provider.create_replacement(&credential).await;
            assert!(unsupported(&result), "{name}: manual create_replacement");
            Status::Manual
        }
    };
    cells.insert("create_replacement", create);

    // A malformed reference: real implementations refuse it before any
    // request; the trait default answers Unsupported.
    let verify = provider
        .verify_replacement("matrix-not-a-reference", &identity)
        .await;
    cells.insert(
        "verify_replacement",
        if unsupported(&verify) {
            Status::Unsupported
        } else {
            Status::Automated
        },
    );

    cells.insert(
        "revoke",
        match provider.manual_revoke(None) {
            Some(_) => Status::Manual,
            None => Status::Automated,
        },
    );

    // A pasted replacement is recorded as `manual` and rollback asks the
    // operator to revoke it by hand.
    let revoke_replacement = match mode {
        ReplacementMode::Manual => Status::Manual,
        ReplacementMode::Automatic => {
            let result = provider.revoke_replacement("matrix-not-a-reference").await;
            if unsupported(&result) {
                Status::Unsupported
            } else {
                Status::Automated
            }
        }
    };
    cells.insert("revoke_replacement", revoke_replacement);
    cells
}

/// `restore` mapped to a status: `Restored` is Automated, `Unsupported`
/// is Unsupported; an error fails the test.
async fn restore_status(provider: &dyn Provider, restore_ref: &str) -> Status {
    match provider.restore(restore_ref).await {
        Ok(RestoreOutcome::Restored) => Status::Automated,
        Ok(RestoreOutcome::Unsupported) => Status::Unsupported,
        Err(e) => panic!("{}: restore failed: {e}", provider.name()),
    }
}

fn xml(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(body)
}

/// An AWS provider against a local IAM that knows the old key's owner and
/// accepts `UpdateAccessKey`, so `restore` can run end to end.
async fn aws_against(server: &MockServer) -> AwsProvider {
    let last_used =
        "<GetAccessKeyLastUsedResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\
         <GetAccessKeyLastUsedResult><UserName>matrix</UserName><AccessKeyLastUsed>\
         <ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed>\
         </GetAccessKeyLastUsedResult><ResponseMetadata><RequestId>r1</RequestId>\
         </ResponseMetadata></GetAccessKeyLastUsedResponse>";
    let update = "<UpdateAccessKeyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\
         <ResponseMetadata><RequestId>r2</RequestId></ResponseMetadata>\
         </UpdateAccessKeyResponse>";
    Mock::given(body_string_contains("Action=GetAccessKeyLastUsed&"))
        .respond_with(xml(last_used.to_owned()))
        .mount(server)
        .await;
    Mock::given(body_string_contains("Action=UpdateAccessKey&"))
        .respond_with(xml(update.to_owned()))
        .mount(server)
        .await;
    let operator_id = ["AK", "IA", "MATRIXOPERATOR01"].concat();
    let operator = Credentials::new(operator_id, filler(40), None, None, "matrix-operator");
    AwsProvider::new()
        .with_region("us-east-1")
        .with_endpoint_url(server.uri())
        .with_operator_credentials(operator)
}

fn assert_cell(tables: &Tables, provider: &str, op: &str, with: Status, without: Status) {
    let row = &tables["Providers"][provider][op];
    assert_eq!(
        row.cell,
        Cell { with, without },
        "docs/providers.md disagrees with the code for {provider} {op}"
    );
}

// T2 (AC2): the doc's cells match what each provider reports.
#[tokio::test]
async fn doc_cells_match_the_providers() {
    let tables = tables(&doc());

    // AWS. `restore` runs against a local IAM; the bare old key id is a
    // restore reference rotate records.
    let server = MockServer::start().await;
    let aws = aws_against(&server).await;
    let mut aws_cells = derive(&aws).await;
    let old_key = ["AK", "IA", "MATRIXTESTKEY001"].concat();
    aws_cells.insert("restore", restore_status(&aws, &old_key).await);
    let mutations: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .filter(|b| b.contains("Action=UpdateAccessKey&"))
        .collect();
    assert_eq!(mutations.len(), 1, "restore reactivates the old key once");

    // GitHub and npm never need a call for these cells.
    let github = GithubProvider::new("http://127.0.0.1:9");
    let mut github_cells = derive(&github).await;
    github_cells.insert("restore", restore_status(&github, "matrix-ref").await);

    let npm = NpmProvider::new("http://127.0.0.1:9").with_operator_token(None);
    let mut npm_cells = derive(&npm).await;
    npm_cells.insert("restore", restore_status(&npm, "matrix-ref").await);

    for (name, cells) in [
        ("aws", aws_cells),
        ("github", github_cells),
        ("npm", npm_cells),
    ] {
        for (op, status) in cells {
            assert_cell(&tables, name, op, status, status);
        }
    }

    // OpenAI with and without an admin key: the doc's two-part cells.
    let admin = SecretValue::from(["sk", "-admin-", &filler(40)].concat());
    // "With" is an admin key and the opt-in to a broader replacement
    // (SHA-291); an admin key alone leaves replacement manual, which the
    // cells say with "or opt-in".
    let with = OpenAiProvider::new("http://127.0.0.1:9", AdminKey::Value(admin.clone()))
        .with_allow_broader_replacement(true);
    let without = OpenAiProvider::new("http://127.0.0.1:9", AdminKey::None);
    let admin_only = OpenAiProvider::new("http://127.0.0.1:9", AdminKey::Value(admin));
    assert_eq!(with.replacement_mode(), ReplacementMode::Automatic);
    assert_eq!(without.replacement_mode(), ReplacementMode::Manual);
    assert_eq!(admin_only.replacement_mode(), ReplacementMode::Manual);
    let admin_only_cells = derive(&admin_only).await;
    let doc_text = doc();
    for op in ["create_replacement", "revoke_replacement"] {
        assert_eq!(admin_only_cells[op], Status::Manual, "{op}");
        let row = doc_text
            .lines()
            .find(|l| {
                l.contains("Automated; Manual without admin key")
                    && l.starts_with(&format!("| `{op}`"))
                    && l.contains("OpenAI admin key")
            })
            .unwrap_or_else(|| panic!("no openai {op} row"));
        assert!(row.contains(WITHOUT_ADMIN_OR_OPT_IN), "{op}: {row}");
    }
    let mut with_cells = derive(&with).await;
    with_cells.insert("restore", restore_status(&with, "matrix-ref").await);
    let mut without_cells = derive(&without).await;
    without_cells.insert("restore", restore_status(&without, "matrix-ref").await);
    for (op, status) in &with_cells {
        assert_cell(&tables, "openai", op, *status, without_cells[op]);
    }

    // Every provider implements these with real calls, so they cannot be
    // derived offline; the code has no Manual or Unsupported path for them.
    for name in PROVIDERS {
        for op in ["check_valid", "describe_scope", "verify"] {
            assert_cell(&tables, name, op, Status::Automated, Status::Automated);
        }
    }
}
