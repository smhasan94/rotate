//! GitHub Actions repository and organization secrets (SHA-253).
//!
//! Actions secret values cannot be read back, so every match is by name
//! (decision D4): the names in [`SecretRef::names`], which the planner
//! builds from the provider's convention and `rotate.yaml`. Names that
//! [`consumer_names`] lists as key-id names hold the access key id; the
//! rest hold the secret. `find` puts key-id matches first in each target so
//! updates in plan order write the id before the secret.
//!
//! `update` and `restore` fetch the target's public key, seal the value
//! with a libsodium sealed box ([`crate::github::seal`]) and `PUT` it. Org
//! secrets keep their `visibility` and selected repositories.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use super::{
    Consumer, ConsumerError, ConsumerMatch, Holds, NotUpdatable, SecretRef, UpdateReceipt,
};
use crate::config::{ActionsTarget, ConsumersConfig, GithubConfig};
use crate::github::{operator_token_from_env, seal, GithubClient, GithubError};
use crate::plan::consumer_names;
use crate::provider::Credential;
use crate::secret::SecretValue;

/// The consumer's stable name.
pub const NAME: &str = "github-actions";

/// Reason shown for a target that answers 404.
pub const NOT_FOUND_REASON: &str = "not found or token lacks access";

#[derive(Deserialize)]
struct ListedSecret {
    name: String,
}

#[derive(Deserialize)]
struct PublicKey {
    key_id: String,
    key: String,
}

#[derive(Deserialize)]
struct OrgSecret {
    visibility: String,
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
}

/// The GitHub Actions secrets consumer.
#[derive(Debug)]
pub struct GithubActionsConsumer {
    client: GithubClient,
    config: ConsumersConfig,
}

impl GithubActionsConsumer {
    /// A consumer searching `config.github_actions.targets` through
    /// `client`. Makes no call.
    pub fn new(client: GithubClient, config: &ConsumersConfig) -> Self {
        Self {
            client,
            config: config.clone(),
        }
    }

    /// A consumer for the loaded config, with the operator token from
    /// `ROTATE_GITHUB_TOKEN` or `GITHUB_TOKEN`. Makes no call.
    pub fn from_config(consumers: &ConsumersConfig, github: &GithubConfig) -> Self {
        let client = GithubClient::new(github.api_url.as_str(), operator_token_from_env());
        Self::new(client, consumers)
    }

    fn targets(&self) -> &[ActionsTarget] {
        &self.config.github_actions.targets
    }

    /// The names to look for, key-id names first, each with what it holds.
    fn wanted<'a>(&self, secret: &'a SecretRef) -> Vec<(&'a str, Holds)> {
        let key_ids = consumer_names(&secret.provider, &self.config).key_id;
        let holds = |name: &str| {
            if key_ids.iter().any(|k| k == name) {
                Holds::KeyId
            } else {
                Holds::Secret
            }
        };
        let mut wanted: Vec<(&str, Holds)> = Vec::new();
        for name in &secret.names {
            if !wanted.iter().any(|(n, _)| n == name) {
                wanted.push((name, holds(name)));
            }
        }
        wanted.sort_by_key(|(_, h)| *h != Holds::KeyId);
        wanted
    }

    /// Parses `github-actions:<target>:<name>` back to a configured target.
    fn parse_ref<'a>(
        &'a self,
        consumer_ref: &'a str,
    ) -> Result<(&'a ActionsTarget, &'a str), ConsumerError> {
        let invalid = || {
            ConsumerError::Permanent(format!(
                "{consumer_ref} is not a GitHub Actions secret of a configured target"
            ))
        };
        let rest = consumer_ref
            .strip_prefix(NAME)
            .and_then(|r| r.strip_prefix(':'))
            .ok_or_else(invalid)?;
        let (target, name) = rest.rsplit_once(':').ok_or_else(invalid)?;
        if !valid_secret_name(name) {
            return Err(invalid());
        }
        let target = self
            .targets()
            .iter()
            .find(|t| t.to_string() == target)
            .ok_or_else(invalid)?;
        Ok((target, name))
    }

    /// Seals the part of `credential` that `target` holds and writes it.
    async fn write(
        &self,
        target: &ConsumerMatch,
        credential: &Credential,
    ) -> Result<(), ConsumerError> {
        if let Err(reason) = &target.updatable {
            return Err(ConsumerError::NotUpdatable(NotUpdatable::clone(reason)));
        }
        let (actions_target, name) = self.parse_ref(&target.consumer_ref)?;
        let value = match (target.holds, credential) {
            (Holds::Secret, _) => credential.secret().clone(),
            (Holds::KeyId, Credential::KeyPair(pair)) => SecretValue::from(pair.key_id.as_str()),
            (Holds::KeyId, Credential::Token(_)) => {
                return Err(ConsumerError::Unsupported(format!(
                    "{} holds an access key id but the credential is a single token",
                    target.consumer_ref
                )))
            }
            (Holds::KeyPair, _) => {
                return Err(ConsumerError::Unsupported(format!(
                    "{} cannot hold both halves of a key pair",
                    target.consumer_ref
                )))
            }
        };
        let base = secrets_path(actions_target);
        let key: PublicKey = self.client.get_json(&format!("{base}/public-key")).await?;
        let mut body = json!({
            "encrypted_value": seal(&key.key, &value)?,
            "key_id": key.key_id,
        });
        if let ActionsTarget::Org(_) = actions_target {
            let existing: OrgSecret = self.client.get_json(&format!("{base}/{name}")).await?;
            if existing.visibility == "selected" {
                let repos: Vec<Repository> = self
                    .client
                    .get_paged(&format!("{base}/{name}/repositories"), Some("repositories"))
                    .await?;
                body["selected_repository_ids"] = repos.iter().map(|r| r.id).collect();
            }
            body["visibility"] = existing.visibility.into();
        }
        self.client
            .put_json(&format!("{base}/{name}"), &body)
            .await?;
        Ok(())
    }
}

/// GitHub secret names: letters, digits and underscores.
fn valid_secret_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn secrets_path(target: &ActionsTarget) -> String {
    match target {
        ActionsTarget::Repo { owner, repo } => format!("/repos/{owner}/{repo}/actions/secrets"),
        ActionsTarget::Org(org) => format!("/orgs/{org}/actions/secrets"),
    }
}

fn secret_ref(target: &ActionsTarget, name: &str) -> String {
    format!("{NAME}:{target}:{name}")
}

#[async_trait]
impl Consumer for GithubActionsConsumer {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn find(&self, secret: &SecretRef) -> Result<Vec<ConsumerMatch>, ConsumerError> {
        let wanted = self.wanted(secret);
        if self.targets().is_empty() || wanted.is_empty() {
            return Ok(Vec::new());
        }
        if !self.client.has_token() {
            return Err(GithubError::NoToken.into());
        }
        let mut found = Vec::new();
        for target in self.targets() {
            let listed = self
                .client
                .get_paged::<ListedSecret>(&secrets_path(target), Some("secrets"))
                .await;
            match listed {
                Ok(listed) => {
                    for (name, holds) in &wanted {
                        if listed.iter().any(|s| s.name == *name) {
                            found.push(
                                ConsumerMatch::by_name(secret_ref(target, name)).holding(*holds),
                            );
                        }
                    }
                }
                Err(GithubError::Status { status: 404, .. }) => found.push(
                    ConsumerMatch::by_name(format!("{NAME}:{target}"))
                        .not_updatable(NOT_FOUND_REASON),
                ),
                Err(GithubError::Status {
                    status: 403,
                    message,
                }) => found.push(
                    ConsumerMatch::by_name(format!("{NAME}:{target}"))
                        .not_updatable(format!("token lacks access: {message}")),
                ),
                Err(other) => return Err(other.into()),
            }
        }
        Ok(found)
    }

    async fn update(
        &self,
        target: &ConsumerMatch,
        new: &Credential,
    ) -> Result<UpdateReceipt, ConsumerError> {
        self.write(target, new).await?;
        Ok(UpdateReceipt {
            consumer_ref: target.consumer_ref.clone(),
            version: None,
        })
    }

    async fn restore(&self, target: &ConsumerMatch, old: &Credential) -> Result<(), ConsumerError> {
        self.write(target, old).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderName;
    use crate::secret::SecretPair;

    fn consumer(targets: &[&str]) -> GithubActionsConsumer {
        let mut config = ConsumersConfig::default();
        config.github_actions.targets = targets
            .iter()
            .map(|t| ActionsTarget::try_from((*t).to_owned()).unwrap())
            .collect();
        config
            .github_actions
            .key_id_names
            .insert(ProviderName::Aws, vec!["CI_AWS_ID".into()]);
        GithubActionsConsumer::new(GithubClient::new("http://127.0.0.1:9", None), &config)
    }

    fn aws_ref(names: &[&str]) -> SecretRef {
        let cred = Credential::KeyPair(SecretPair::new(
            "KEYIDUNITTEST",
            SecretValue::from("unit-secret-1"),
        ));
        SecretRef::new("aws", &cred).with_names(names.iter().copied())
    }

    #[test]
    fn wanted_puts_key_ids_first_and_classifies() {
        let c = consumer(&["acme/api"]);
        let secret = aws_ref(&[
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "CI_AWS_ID",
            "AWS_SECRET_ACCESS_KEY",
        ]);
        let wanted = c.wanted(&secret);
        assert_eq!(
            wanted,
            [
                ("AWS_ACCESS_KEY_ID", Holds::KeyId),
                ("CI_AWS_ID", Holds::KeyId),
                ("AWS_SECRET_ACCESS_KEY", Holds::Secret),
            ]
        );
    }

    #[test]
    fn parse_ref_accepts_only_configured_targets() {
        let c = consumer(&["acme/api", "org:acme"]);
        let (t, n) = c.parse_ref("github-actions:acme/api:NPM_TOKEN").unwrap();
        assert_eq!((t.to_string().as_str(), n), ("acme/api", "NPM_TOKEN"));
        let (t, _) = c.parse_ref("github-actions:org:acme:NPM_TOKEN").unwrap();
        assert_eq!(*t, ActionsTarget::Org("acme".into()));
        for bad in [
            "github-actions:other/repo:X",
            "github-actions:acme/api",
            "github-actions:acme/api:../x",
            "sm:acme/api:X",
        ] {
            assert!(c.parse_ref(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn no_targets_or_names_is_empty_without_token() {
        let c = consumer(&[]);
        assert!(c
            .find(&aws_ref(&["AWS_ACCESS_KEY_ID"]))
            .await
            .unwrap()
            .is_empty());
        let c = consumer(&["acme/api"]);
        assert!(c.find(&aws_ref(&[])).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_token_fails_find() {
        let c = consumer(&["acme/api"]);
        let err = c.find(&aws_ref(&["AWS_ACCESS_KEY_ID"])).await.unwrap_err();
        assert!(err.to_string().contains("ROTATE_GITHUB_TOKEN"));
    }

    #[tokio::test]
    async fn update_refuses_not_updatable_and_key_pair() {
        let c = consumer(&["acme/api"]);
        let cred = Credential::Token(SecretValue::from("unit-tok-2"));
        let blocked = ConsumerMatch::by_name("github-actions:acme/api").not_updatable("x");
        assert!(matches!(
            c.update(&blocked, &cred).await,
            Err(ConsumerError::NotUpdatable(_))
        ));
        let key_id = ConsumerMatch::by_name("github-actions:acme/api:X").holding(Holds::KeyId);
        assert!(matches!(
            c.update(&key_id, &cred).await,
            Err(ConsumerError::Unsupported(_))
        ));
        let pair = ConsumerMatch::by_name("github-actions:acme/api:X").holding(Holds::KeyPair);
        assert!(matches!(
            c.restore(&pair, &cred).await,
            Err(ConsumerError::Unsupported(_))
        ));
    }
}
