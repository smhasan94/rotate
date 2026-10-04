//! `rotate plan --check-permissions` (SHA-270): read-only probes of the
//! operator's own permissions, run after the plan is built, so missing
//! permissions show up before `rotate apply` instead of halfway through it.
//!
//! - AWS: `sts:GetCallerIdentity` with the operator's credentials for its
//!   own ARN, then `iam:SimulatePrincipalPolicy` with the provider's
//!   [`REQUIRED_ACTIONS`](crate::provider::aws::REQUIRED_ACTIONS) on the key
//!   owner's ARN, and with the Secrets Manager
//!   [`WRITE_ACTIONS`](crate::consumer::aws_secrets_manager::WRITE_ACTIONS)
//!   on each matched entry named by ARN. Every action the simulation does
//!   not allow becomes a blocker.
//! - GitHub Actions: `GET .../actions/secrets/public-key` once per target
//!   (see [`GithubActionsConsumer::check_write`]). A target the token cannot
//!   write marks its matches not updatable with
//!   [`LACKS_SECRETS_WRITE`](crate::consumer::github_actions::LACKS_SECRETS_WRITE).
//!
//! The other providers have no read-only way to test a permission, so they
//! are not probed. Nothing here changes state, and the plan keeps its JSON
//! shape: results go into `blockers` and consumer reasons. A probe that
//! cannot run is a warning for stderr, never a blocker.

use std::collections::BTreeMap;

use crate::consumer::aws_secrets_manager::{self, secret_id, WRITE_ACTIONS};
use crate::consumer::github_actions::{
    self, GithubActionsConsumer, WriteAccess, LACKS_SECRETS_WRITE,
};
use crate::plan::{blockers, Plan, PlannedRotation, MANUAL_REVOKE_BLOCKER};
use crate::provider::aws::{self, AwsProvider, REQUIRED_ACTIONS};

/// How every permission blocker starts.
pub const MISSING_PERMISSION: &str = "operator lacks";

/// The probes, with the same configuration the real plugins use.
#[derive(Debug)]
pub struct PermissionChecker {
    aws: AwsProvider,
    actions: GithubActionsConsumer,
}

impl PermissionChecker {
    /// A checker using `aws` for the IAM simulation and `actions` for the
    /// GitHub write probe. Makes no call.
    pub fn new(aws: AwsProvider, actions: GithubActionsConsumer) -> Self {
        Self { aws, actions }
    }

    /// Probes the permissions every rotation in `plan` needs and records
    /// what is missing in it. Returns warnings for probes that could not
    /// run. Read-only.
    pub async fn check(&self, plan: &mut Plan) -> Vec<String> {
        let mut warnings = Warnings::default();
        let mut github: BTreeMap<String, WriteAccess> = BTreeMap::new();
        let mut principal: Option<Option<String>> = None;
        for rotation in &mut plan.rotations {
            self.check_github(rotation, &mut github, &mut warnings)
                .await;
            let missing = self
                .check_aws(rotation, &mut principal, &mut warnings)
                .await;
            let manual = rotation.blockers.iter().any(|b| b == MANUAL_REVOKE_BLOCKER);
            rotation.blockers = blockers(rotation);
            if manual {
                rotation.blockers.push(MANUAL_REVOKE_BLOCKER.to_owned());
            }
            rotation.blockers.extend(missing);
        }
        warnings.0
    }

    /// Marks every updatable Actions match whose target the token cannot
    /// write. Each target is probed once per run.
    async fn check_github(
        &self,
        rotation: &mut PlannedRotation,
        probed: &mut BTreeMap<String, WriteAccess>,
        warnings: &mut Warnings,
    ) {
        for planned in &mut rotation.consumers {
            if planned.consumer != github_actions::NAME || !planned.found.is_updatable() {
                continue;
            }
            let consumer_ref = planned.found.consumer_ref.clone();
            let Some(target) = self.actions.target_of(&consumer_ref) else {
                continue;
            };
            let access = match probed.get(&target) {
                Some(access) => access.clone(),
                None => match self.actions.check_write(&consumer_ref).await {
                    Ok(access) => {
                        if access == WriteAccess::Unconfirmed {
                            warnings.push(format!(
                                "github-actions {target}: the token can read the public key, but \
                                 GitHub does not expose fine-grained permissions; make sure it \
                                 has Secrets: read and write"
                            ));
                        }
                        probed.insert(target.clone(), access.clone());
                        access
                    }
                    Err(err) => {
                        warnings.push(format!(
                            "github-actions {target}: write permission not checked: {err}"
                        ));
                        continue;
                    }
                },
            };
            if access == WriteAccess::Lacking {
                planned.found = planned.found.clone().not_updatable(LACKS_SECRETS_WRITE);
            }
        }
    }

    /// The permission blockers for `rotation` from the IAM simulation:
    /// the AWS provider's actions on the key owner, and the Secrets Manager
    /// write actions on each updatable entry named by ARN.
    async fn check_aws(
        &self,
        rotation: &PlannedRotation,
        principal: &mut Option<Option<String>>,
        warnings: &mut Warnings,
    ) -> Vec<String> {
        let mut targets: Vec<(&[&str], String)> = Vec::new();
        if rotation.provider == aws::NAME {
            match &rotation.scope {
                Some(scope) => targets.push((REQUIRED_ACTIONS, scope.identity.to_string())),
                None => warnings.push(format!(
                    "rotation {}: the key owner is unknown, so its IAM permissions were not \
                     simulated",
                    rotation.rotation_id
                )),
            }
        }
        for planned in &rotation.consumers {
            if planned.consumer != aws_secrets_manager::NAME || !planned.found.is_updatable() {
                continue;
            }
            match secret_id(&planned.found.consumer_ref) {
                Some(id) if id.starts_with("arn:") => targets.push((WRITE_ACTIONS, id)),
                Some(id) => warnings.push(format!(
                    "aws-secrets-manager {id}: named by name, so its permissions were not \
                     simulated; list it by ARN in rotate.yaml to check them"
                )),
                None => {}
            }
        }
        if targets.is_empty() {
            return Vec::new();
        }
        if principal.is_none() {
            *principal = Some(match self.aws.operator_principal().await {
                Ok(arn) => Some(arn),
                Err(err) => {
                    warnings.push(format!("AWS permissions not checked: {err}"));
                    None
                }
            });
        }
        let Some(Some(arn)) = principal.as_ref() else {
            return Vec::new();
        };
        let mut missing = Vec::new();
        for (actions, resource) in targets {
            match self.aws.simulate_operator(arn, actions, &resource).await {
                Ok(denied) => missing.extend(denied.into_iter().map(|action| {
                    format!("{MISSING_PERMISSION} {action} on {resource} (IAM policy simulation)")
                })),
                Err(err) => warnings.push(format!("AWS permissions not checked: {err}")),
            }
        }
        missing
    }
}

/// Warnings in order, each once.
#[derive(Default)]
struct Warnings(Vec<String>);

impl Warnings {
    fn push(&mut self, warning: String) {
        if !self.0.contains(&warning) {
            self.0.push(warning);
        }
    }
}
