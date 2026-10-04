//! SHA-269: the user docs stay in step with the code.
//!
//! T1 runs `rotate --help` and every subcommand's `--help` and checks that
//! each flag is named in `docs/usage.md` or `docs/non-interactive.md`, and
//! that every `Exit` code has a row in both docs' exit code tables. T2
//! parses the complete example in `docs/config.md` and destructures every
//! config struct without `..`, so a new field fails to compile here until
//! it is added (and then documented with a `Default:` line). T3 runs the
//! command blocks of `docs/usage.md` marked `<!-- test: <scenario> -->`
//! against the acceptance-test models (`tests/e2e`) and checks each exit
//! code and expected output. T4 checks `docs/security.md` states the
//! brief's four safety guarantees word for word and lists its limits.

mod common;
mod e2e;

use std::path::Path;

use regex::Regex;

use rotate::config::{
    AwsConfig, ConsumersConfig, FileConfig, GithubActionsConfig, GithubConfig, NpmConfig,
    OpenAiConfig, ProvidersConfig, SecretsManagerConfig, TagFilter,
};

use e2e::{stdout, E2e};

const USAGE: &str = include_str!("../docs/usage.md");
const NON_INTERACTIVE: &str = include_str!("../docs/non-interactive.md");
const CONFIG: &str = include_str!("../docs/config.md");
const SECURITY: &str = include_str!("../docs/security.md");
const BRIEF: &str = include_str!("../CLAUDE.md");
const EXIT_SRC: &str = include_str!("../src/exit.rs");

/// The rotation id the docs use in examples. T3 replaces it with the id
/// the scenario's own plan assigned.
const EXAMPLE_ID: &str = "rot-5f36d3cd";

/// The report file name the docs use. T3 writes the fixture under it.
const DOC_REPORT: &str = "trufflehog-report.json";

/// The fenced block of `lang` that follows `marker`.
fn block_after(doc: &str, marker: &str, lang: &str) -> String {
    let start = doc
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} in the doc"));
    let rest = &doc[start + marker.len()..];
    let fence = format!("```{lang}\n");
    let open = rest
        .find(&fence)
        .unwrap_or_else(|| panic!("no {lang} block after {marker:?}"));
    assert!(
        rest[..open].trim().is_empty(),
        "text between {marker:?} and its block"
    );
    let body = &rest[open + fence.len()..];
    let close = body.find("```").expect("unterminated block");
    body[..close].to_owned()
}

/// `text` with every run of whitespace collapsed to one space.
fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// T1 (AC1): flags and exit codes
// ---------------------------------------------------------------------------

fn help(args: &[&str]) -> String {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"))
        .args(args)
        .arg("--help")
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success(), "rotate {args:?} --help failed");
    String::from_utf8(output.stdout).unwrap()
}

/// The visible subcommands listed by `rotate --help`, without `help`.
fn subcommands(root_help: &str) -> Vec<String> {
    let section = root_help
        .split("Commands:\n")
        .nth(1)
        .expect("no Commands section");
    let name = Regex::new(r"^  ([a-z][a-z-]*)\s").unwrap();
    section
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| name.captures(l).map(|c| c[1].to_owned()))
        .filter(|n| n != "help")
        .collect()
}

/// Every long and short flag in the Options section of a help text.
fn flags(help: &str) -> Vec<String> {
    let section = help.split("Options:\n").nth(1).expect("no Options section");
    let flag = Regex::new(r"(?m)^\s+(?:(-[A-Za-z]), )?(--[a-z][a-z0-9-]*)").unwrap();
    let mut found = Vec::new();
    for c in flag.captures_iter(section) {
        if let Some(short) = c.get(1) {
            found.push(short.as_str().to_owned());
        }
        found.push(c[2].to_owned());
    }
    found
}

/// Whether `doc` names `flag`: a long flag as a whole word, a short flag
/// in backticks.
fn mentions(doc: &str, flag: &str) -> bool {
    if flag.starts_with("--") {
        Regex::new(&format!(
            r"(^|[^A-Za-z0-9-]){}($|[^A-Za-z0-9-])",
            regex::escape(flag)
        ))
        .unwrap()
        .is_match(doc)
    } else {
        doc.contains(&format!("`{flag}`"))
    }
}

// T1 (AC1)
#[test]
fn t1_every_help_flag_is_documented() {
    let root = help(&[]);
    let commands = subcommands(&root);
    assert_eq!(commands, ["plan", "apply", "rollback", "status"]);

    let mut missing = Vec::new();
    let mut checked = 0;
    for command in std::iter::once(None).chain(commands.iter().map(Some)) {
        let text = match command {
            None => root.clone(),
            Some(c) => help(&[c.as_str()]),
        };
        for flag in flags(&text) {
            checked += 1;
            if !mentions(USAGE, &flag) && !mentions(NON_INTERACTIVE, &flag) {
                missing.push(format!("{} {flag}", command.map_or("rotate", |c| c)));
            }
        }
    }
    // The parser really read the help: the CLI has around twenty flags.
    assert!(checked > 40, "only {checked} flags found");
    assert!(
        missing.is_empty(),
        "flags in --help but not in docs/usage.md or docs/non-interactive.md: {missing:?}"
    );
}

// T1 (AC1)
#[test]
fn t1_flag_parser_and_matcher() {
    let help = "Options:\n      --config <PATH>  x\n  -v, --verbose...  y\n      --all  z\n";
    assert_eq!(flags(help), ["--config", "-v", "--verbose", "--all"]);
    assert!(mentions("use `--all` here", "--all"));
    assert!(!mentions("use --all-features", "--all"));
    assert!(!mentions("use --tall", "--all"));
    assert!(mentions("`-v`, `--verbose`", "-v"));
    assert!(!mentions("-vvv", "-v"));
}

/// The codes of the `Exit` enum, read from its source.
fn exit_codes() -> Vec<u8> {
    let variant = Regex::new(r"(?m)^\s+[A-Z][A-Za-z]* = (\d+),").unwrap();
    variant
        .captures_iter(EXIT_SRC)
        .map(|c| c[1].parse().unwrap())
        .collect()
}

// T1 (AC1)
#[test]
fn t1_every_exit_code_is_documented() {
    let codes = exit_codes();
    assert_eq!(
        codes,
        [0, 1, 2, 3, 4],
        "src/exit.rs changed: update the docs"
    );
    for (name, doc) in [
        ("docs/usage.md", USAGE),
        ("docs/non-interactive.md", NON_INTERACTIVE),
    ] {
        for code in codes.iter().map(u8::to_string).chain(["101".to_owned()]) {
            assert!(
                doc.contains(&format!("\n| {code} | ")),
                "{name} has no exit code row for {code}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// T2 (AC2): every config field
// ---------------------------------------------------------------------------

/// The complete example in docs/config.md.
fn full_config() -> FileConfig {
    let yaml = block_after(CONFIG, "<!-- full-config -->", "yaml");
    rotate::config::parse(&yaml, Path::new("docs/config.md")).expect("the example is invalid")
}

/// Every field as `(dotted key, set in the example)`. Each struct is
/// destructured without `..`: a new field does not compile until it is
/// listed here.
fn fields(config: &FileConfig) -> Vec<(&'static str, bool)> {
    let FileConfig {
        overlap_window,
        audit_log,
        state_file,
        consumers,
        providers,
    } = config;
    let ConsumersConfig {
        github_actions,
        aws_secrets_manager,
    } = consumers;
    let GithubActionsConfig {
        targets,
        secret_names,
        key_id_names,
    } = github_actions;
    let SecretsManagerConfig {
        secrets,
        tag_filters,
        json_keys,
    } = aws_secrets_manager;
    let (tag_key, tag_values) = match tag_filters.first() {
        Some(TagFilter { key, values }) => (!key.is_empty(), !values.is_empty()),
        None => (false, false),
    };
    let ProvidersConfig {
        aws,
        github,
        npm,
        openai,
    } = providers;
    let AwsConfig {
        region,
        endpoint_url,
    } = aws;
    let GithubConfig {
        api_url: github_api,
    } = github;
    let NpmConfig { registry } = npm;
    let OpenAiConfig {
        admin_key_env,
        api_url: openai_api,
    } = openai;
    vec![
        ("overlap_window", overlap_window.is_some()),
        ("audit_log", audit_log.is_some()),
        ("state_file", state_file.is_some()),
        ("consumers.github_actions.targets", !targets.is_empty()),
        (
            "consumers.github_actions.secret_names",
            !secret_names.is_empty(),
        ),
        (
            "consumers.github_actions.key_id_names",
            !key_id_names.is_empty(),
        ),
        ("consumers.aws_secrets_manager.secrets", !secrets.is_empty()),
        (
            "consumers.aws_secrets_manager.tag_filters",
            !tag_filters.is_empty(),
        ),
        ("consumers.aws_secrets_manager.tag_filters[].key", tag_key),
        (
            "consumers.aws_secrets_manager.tag_filters[].values",
            tag_values,
        ),
        (
            "consumers.aws_secrets_manager.json_keys",
            json_keys.is_some(),
        ),
        ("providers.aws.region", region.is_some()),
        ("providers.aws.endpoint_url", endpoint_url.is_some()),
        (
            "providers.github.api_url",
            *github_api != GithubConfig::default().api_url,
        ),
        (
            "providers.npm.registry",
            *registry != NpmConfig::default().registry,
        ),
        (
            "providers.openai.admin_key_env",
            *admin_key_env != OpenAiConfig::default().admin_key_env,
        ),
        (
            "providers.openai.api_url",
            *openai_api != OpenAiConfig::default().api_url,
        ),
    ]
}

/// The `### `key`` sections of docs/config.md, as `(key, body)`.
fn field_sections() -> Vec<(String, String)> {
    let fields = CONFIG
        .split("\n## Fields\n")
        .nth(1)
        .expect("no Fields section");
    let fields = fields.split("\n## ").next().unwrap();
    fields
        .split("\n### ")
        .skip(1)
        .map(|section| {
            let (heading, body) = section.split_once('\n').unwrap_or((section, ""));
            let key = heading.trim().trim_matches('`').to_owned();
            (key, body.to_owned())
        })
        .collect()
}

// T2 (AC2)
#[test]
fn t2_every_config_field_is_documented_with_its_default() {
    let config = full_config();
    let fields = fields(&config);
    let sections = field_sections();

    let unset: Vec<_> = fields.iter().filter(|(_, set)| !set).collect();
    assert!(
        unset.is_empty(),
        "the complete example in docs/config.md leaves these at their default: {unset:?}"
    );
    for (key, _) in &fields {
        let body = sections
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, b)| b)
            .unwrap_or_else(|| panic!("docs/config.md has no `### `{key}`` section"));
        assert!(
            body.lines().any(|l| l.starts_with("Default:")),
            "docs/config.md: {key} has no \"Default:\" line"
        );
        assert!(
            body.lines().any(|l| l.starts_with("Type:")),
            "docs/config.md: {key} has no \"Type:\" line"
        );
    }
    // And no section documents a field that does not exist.
    for (key, _) in &sections {
        assert!(
            fields.iter().any(|(k, _)| k == key),
            "docs/config.md documents {key}, which is not a config field"
        );
    }
}

// T2 (AC2): the documented defaults are the code's.
#[test]
fn t2_documented_defaults_match_the_code() {
    let defaults = [
        (
            "overlap_window",
            rotate::config::Overlap::default().to_string(),
        ),
        ("audit_log", rotate::config::DEFAULT_AUDIT_LOG.to_owned()),
        ("state_file", rotate::config::DEFAULT_STATE_FILE.to_owned()),
        (
            "providers.github.api_url",
            GithubConfig::default().api_url.to_string(),
        ),
        (
            "providers.npm.registry",
            NpmConfig::default().registry.to_string(),
        ),
        (
            "providers.openai.admin_key_env",
            OpenAiConfig::default().admin_key_env,
        ),
        (
            "providers.openai.api_url",
            OpenAiConfig::default().api_url.to_string(),
        ),
    ];
    let sections = field_sections();
    for (key, value) in defaults {
        let body = &sections.iter().find(|(k, _)| k == key).unwrap().1;
        let line = body.lines().find(|l| l.starts_with("Default:")).unwrap();
        assert!(
            line.contains(&format!("`{value}`")),
            "docs/config.md: {key} default should be `{value}`: {line}"
        );
    }
    // An empty file sets nothing, as the doc says.
    assert_eq!(
        rotate::config::parse("# only a comment\n", Path::new("x")).unwrap(),
        FileConfig::default()
    );
}

// ---------------------------------------------------------------------------
// T3 (AC3): the usage guide runs as written
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct DocCommand {
    line: String,
    exit: Option<i32>,
    expect: Vec<String>,
}

/// The `<!-- test: <scenario> -->` sh blocks of docs/usage.md, grouped by
/// scenario in the order they appear.
fn scenarios() -> Vec<(String, Vec<DocCommand>)> {
    let marker = Regex::new(r"(?m)^<!-- test: ([a-z0-9-]+) -->$").unwrap();
    let mut scenarios: Vec<(String, Vec<DocCommand>)> = Vec::new();
    for c in marker.captures_iter(USAGE) {
        let name = c[1].to_owned();
        if name == "rotate.yaml" {
            continue;
        }
        let block = block_after(&USAGE[c.get(0).unwrap().start()..], &c[0], "sh");
        let index = match scenarios.iter().position(|(n, _)| *n == name) {
            Some(i) => i,
            None => {
                scenarios.push((name.clone(), Vec::new()));
                scenarios.len() - 1
            }
        };
        let commands = &mut scenarios[index].1;
        let mut in_block = 0;
        for line in block.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if let Some(code) = line.strip_prefix("# exit: ") {
                let last = commands.last_mut().expect("# exit before a command");
                assert!(in_block > 0, "# exit before a command in {name}");
                last.exit = Some(code.parse().expect("exit code"));
            } else if let Some(text) = line.strip_prefix("# expect: ") {
                assert!(in_block > 0, "# expect before a command in {name}");
                let last = commands.last_mut().unwrap();
                last.expect.push(text.to_owned());
            } else if line.starts_with('#') {
                continue;
            } else {
                assert!(
                    line.starts_with("rotate "),
                    "tested block in {name} runs something other than rotate: {line}"
                );
                in_block += 1;
                commands.push(DocCommand {
                    line: line.to_owned(),
                    exit: None,
                    expect: Vec::new(),
                });
            }
        }
    }
    scenarios
}

/// The doc's `rotate.yaml` with the models' endpoints added, so the real
/// plugins talk to the local server.
fn config_for(uri: &str) -> String {
    let yaml = block_after(USAGE, "<!-- test: rotate.yaml -->", "yaml");
    rotate::config::parse(&yaml, Path::new("docs/usage.md")).expect("the doc's rotate.yaml");
    let mut doc: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let providers = doc
        .get_mut("providers")
        .and_then(serde_norway::Value::as_mapping_mut)
        .expect("the doc's rotate.yaml sets providers");
    let mut aws = providers
        .get("aws")
        .and_then(serde_norway::Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    aws.insert("endpoint_url".into(), uri.into());
    providers.insert("aws".into(), aws.into());
    let mut github = serde_norway::Mapping::new();
    github.insert("api_url".into(), uri.into());
    providers.insert("github".into(), github.into());
    serde_norway::to_string(&doc).unwrap()
}

// T3 (AC3)
#[test]
fn t3_scenarios_are_parsed() {
    let scenarios = scenarios();
    let names: Vec<&str> = scenarios.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["first-run", "overlap", "wait"]);
    for (name, commands) in &scenarios {
        assert!(!commands.is_empty(), "{name}");
        for command in commands {
            assert!(
                command.exit.is_some(),
                "{name}: `{}` has no # exit comment",
                command.line
            );
        }
    }
}

// T3 (AC3)
#[tokio::test(flavor = "multi_thread")]
async fn t3_usage_guide_runs_as_written() {
    for (name, commands) in scenarios() {
        let e2e = E2e::start_with_github().await;
        std::fs::write(e2e.file("rotate.yaml"), config_for(&e2e.rec.uri())).unwrap();
        std::fs::copy(e2e.file("report.ndjson"), e2e.file(DOC_REPORT)).unwrap();
        let mut id: Option<String> = None;
        for command in commands {
            let mut args: Vec<String> = command
                .line
                .split_whitespace()
                .skip(1)
                .map(str::to_owned)
                .collect();
            for arg in &mut args {
                if arg == EXAMPLE_ID {
                    *arg = id.get_or_insert_with(|| e2e.rotation_id()).clone();
                }
            }
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let output = e2e.run(&args);
            let out = stdout(&output);
            let all = format!("{out}{}", String::from_utf8_lossy(&output.stderr));
            assert_eq!(
                output.status.code(),
                command.exit,
                "{name}: `{}` exit code\n{out}",
                command.line
            );
            for text in &command.expect {
                assert!(
                    all.contains(text.as_str()),
                    "{name}: `{}` should print {text:?}\n{out}",
                    command.line
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T4 (AC4): the security model
// ---------------------------------------------------------------------------

/// The brief's safety requirements, from CLAUDE.md, one per clause.
fn brief_guarantees() -> Vec<String> {
    let start = BRIEF
        .find("Safety requirements (non-negotiable):")
        .expect("no safety requirements in CLAUDE.md");
    let paragraph = BRIEF[start..].split("\n\n").next().unwrap();
    let text = squash(paragraph);
    let text = text
        .strip_prefix("Safety requirements (non-negotiable): ")
        .unwrap()
        .trim_end_matches('.');
    text.split("; ").map(str::to_owned).collect()
}

/// `sentence` with its first letter upper-cased and a full stop.
fn as_sentence(sentence: &str) -> String {
    let mut chars = sentence.chars();
    let first = chars.next().unwrap().to_uppercase().collect::<String>();
    format!("{first}{}.", chars.as_str())
}

// T4 (AC4)
#[test]
fn t4_security_doc_states_the_four_guarantees_and_limits() {
    let guarantees = brief_guarantees();
    assert_eq!(guarantees.len(), 4, "{guarantees:?}");
    let doc = squash(SECURITY);
    for guarantee in &guarantees {
        assert!(
            doc.contains(&as_sentence(guarantee)),
            "docs/security.md does not state {guarantee:?} verbatim"
        );
    }

    let limits = SECURITY
        .split("\n## Limits\n")
        .nth(1)
        .expect("docs/security.md has no \"## Limits\" heading");
    let limits = limits.split("\n## ").next().unwrap();
    let bullets = limits.lines().filter(|l| l.starts_with("- ")).count();
    assert!(bullets >= 3, "only {bullets} limits");
    assert!(
        limits.to_lowercase().contains("memory dump"),
        "the limits do not mention memory dumps"
    );
}
