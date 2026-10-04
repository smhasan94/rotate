//! SHA-270: `docs/permissions.md` stays in sync with the code.
//!
//! T1 parses the minimal IAM policy from the doc and compares its actions
//! with the `REQUIRED_ACTIONS` the AWS provider and the Secrets Manager
//! consumer declare. A second test scans those two source files for SDK
//! operation calls, so a new call fails here until the constant (and then
//! the doc) names it. T3 checks the doc has every required section.

use std::collections::BTreeSet;

use regex::Regex;
use serde_json::Value;

use rotate::consumer::aws_secrets_manager;
use rotate::provider::aws;

const DOC: &str = include_str!("../docs/permissions.md");
const AWS_SRC: &str = include_str!("../src/provider/aws.rs");
const SM_SRC: &str = include_str!("../src/consumer/aws_secrets_manager.rs");

/// The first JSON code block after `heading`.
fn json_block_after(heading: &str) -> Value {
    let start = DOC
        .find(heading)
        .unwrap_or_else(|| panic!("no {heading:?} in docs/permissions.md"));
    let rest = &DOC[start..];
    let open = rest.find("```json\n").expect("no json block") + "```json\n".len();
    let close = rest[open..].find("```").expect("unterminated json block");
    serde_json::from_str(&rest[open..open + close]).expect("the policy is not valid JSON")
}

/// Every action an IAM policy document allows.
fn policy_actions(policy: &Value) -> BTreeSet<String> {
    let mut actions = BTreeSet::new();
    for statement in policy["Statement"].as_array().expect("Statement array") {
        assert_eq!(statement["Effect"], "Allow", "{statement}");
        match &statement["Action"] {
            Value::String(action) => {
                actions.insert(action.clone());
            }
            Value::Array(list) => {
                actions.extend(list.iter().map(|a| a.as_str().unwrap().to_owned()));
            }
            other => panic!("unexpected Action {other}"),
        }
        assert!(statement["Resource"].is_string(), "{statement}");
    }
    actions
}

fn set(lists: &[&[&str]]) -> BTreeSet<String> {
    lists
        .iter()
        .flat_map(|l| l.iter().map(|a| (*a).to_owned()))
        .collect()
}

// T1 (AC1)
#[test]
fn doc_policy_equals_required_actions() {
    let actions = policy_actions(&json_block_after("### Minimal IAM policy"));
    let expected = set(&[
        aws::REQUIRED_ACTIONS,
        aws::CHECK_PERMISSIONS_ACTIONS,
        aws_secrets_manager::REQUIRED_ACTIONS,
    ]);
    assert_eq!(actions, expected);
    assert!(!actions.contains("iam:DeleteAccessKey"));
    assert!(!actions.iter().any(|a| a.contains('*')), "{actions:?}");
    // The write actions the probe simulates are a subset of the consumer's.
    for action in aws_secrets_manager::WRITE_ACTIONS {
        assert!(aws_secrets_manager::REQUIRED_ACTIONS.contains(action));
    }
}

/// `get_access_key_last_used` as `GetAccessKeyLastUsed`.
fn pascal(snake: &str) -> String {
    snake
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// The AWS SDK operations `src` calls outside its unit tests, as
/// `<prefix>:<Operation>`; `GetCallerIdentity` is always `sts:`.
fn sdk_calls(src: &str, prefix: &str) -> BTreeSet<String> {
    let code = src.split("#[cfg(test)]").next().unwrap();
    let call = Regex::new(
        r"\.((?:get|list|create|update|delete|put|simulate|describe|tag|untag|attach|detach)_[a-z_]+)\(\)",
    )
    .unwrap();
    call.captures_iter(code)
        .map(|c| {
            let op = pascal(&c[1]);
            if op == "GetCallerIdentity" {
                format!("sts:{op}")
            } else {
                format!("{prefix}:{op}")
            }
        })
        .collect()
}

// T1 (AC1): the constants match what the code calls.
#[test]
fn required_actions_match_sdk_calls() {
    let aws_calls = sdk_calls(AWS_SRC, "iam");
    assert_eq!(
        aws_calls,
        set(&[aws::REQUIRED_ACTIONS, aws::CHECK_PERMISSIONS_ACTIONS])
    );
    assert!(!aws_calls.contains("iam:DeleteAccessKey"));
    assert_eq!(
        sdk_calls(SM_SRC, "secretsmanager"),
        set(&[aws_secrets_manager::REQUIRED_ACTIONS])
    );
}

// T3 (AC3)
#[test]
fn doc_has_every_required_section() {
    for heading in [
        "## By command",
        "## Checking permissions before apply (`--check-permissions`)",
        "## AWS IAM access keys (provider `aws`)",
        "### Minimal IAM policy",
        "### Scoping the policy",
        "## AWS Secrets Manager (consumer `aws-secrets-manager`)",
        "## GitHub Actions secrets (consumer `github-actions`)",
        "## GitHub tokens (provider `github`)",
        "## npm tokens (provider `npm`)",
        "## OpenAI API keys (provider `openai`)",
    ] {
        assert!(
            DOC.lines().any(|l| l == heading),
            "docs/permissions.md has no {heading:?} heading"
        );
    }
    for text in [
        "```json",
        "iam:DeleteAccessKey",
        // GitHub scopes and fine-grained permissions.
        "`repo` scope",
        "`admin:org` scope",
        "\"Secrets: read and write\"",
        // npm and OpenAI requirements.
        "`npm login` session token",
        "ROTATE_NPM_TOKEN",
        "Admin API key",
        "platform.openai.com/settings/organization/admin-keys",
        // The flag.
        "rotate plan --check-permissions",
        "iam:SimulatePrincipalPolicy",
        "/actions/secrets/public-key",
        rotate::consumer::github_actions::LACKS_SECRETS_WRITE,
        // Every command.
        "`rotate plan`",
        "`rotate apply`",
        "`rotate rollback`",
        "`rotate status`",
        "providers.md",
    ] {
        assert!(DOC.contains(text), "docs/permissions.md lacks {text:?}");
    }
}
