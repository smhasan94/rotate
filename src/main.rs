//! `rotate` entry point.
//!
//! Every byte this binary prints goes through `rotate::console::Console`,
//! which redacts it (SHA-246). `clippy.toml` rejects `println!` and friends.

mod cli;
mod exit;
mod providers;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use rotate::apply::{
    self, Confirmation, Executor, QuestionWriter, ReplacementSource, RunStatus, TtyPrompt,
};
use rotate::assess::{assess, AssessOptions};
use rotate::audit::AuditLog;
use rotate::config::{Config, ConfigError};
use rotate::console::{self, Console};
use rotate::consumer::ConsumerRegistry;
use rotate::finding::Finding;
use rotate::plan;
use rotate::provider::{ProviderRegistry, ReplacementMode};
use rotate::report::{read_report, ReportError};
use rotate::rollback;
use rotate::secret::SecretValue;
use rotate::state::{StateError, StateStore};

use crate::cli::{ApplyArgs, Cli, Command, InputArgs, RollbackArgs, StatusArgs};
use crate::exit::Exit;

fn main() -> ExitCode {
    console::install_panic_hook();
    let mut console = Console::stdio();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let usage = Cli::command().render_usage();
            let code = console.report_parse_error(&err, &usage);
            return ExitCode::from(u8::try_from(code).unwrap_or(Exit::Usage as u8));
        }
    };
    install_logging(cli.global.verbose);
    // Config errors are usage errors: the operator fixes the file or flag.
    let config = match Config::load(&cli.global.overrides()) {
        Ok(config) => config,
        Err(ConfigError::Read { source, .. }) => {
            // The path may be something the operator typed, such as a token
            // pasted after --config, so it is not repeated.
            let _ = writeln!(
                console.err(),
                "error: could not read the config file ({}). Secrets must be passed with --stdin, never as an argument.",
                source.kind()
            );
            return Exit::Usage.into();
        }
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            return Exit::Usage.into();
        }
    };
    // A secret read for the hidden test command lives until its error has
    // been printed, as real inputs must: a value is redacted only while it
    // is registered.
    #[cfg(feature = "test-commands")]
    let _held;
    #[cfg(feature = "test-commands")]
    let result = if let Command::TestConsole { mode } = cli.subcommand() {
        match rotate::secret::SecretValue::from_reader(std::io::stdin().lock()) {
            Ok(secret) => {
                _held = secret;
                test_console(&mut console, mode, &_held)
            }
            Err(err) => Err(err.into()),
        }
    } else {
        run(&mut console, cli.subcommand(), &config, cli.global.json)
    };
    #[cfg(not(feature = "test-commands"))]
    let result = run(&mut console, cli.subcommand(), &config, cli.global.json);
    // Writes the mock call log when a test scenario asks for it; a no-op in
    // release builds (SHA-250).
    providers::finish();
    match result {
        Ok(exit) => exit.into(),
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            Exit::RotationFailed.into()
        }
    }
}

/// Sends tracing events to stderr through the redaction layer (SHA-218), at
/// the level the `-v` count selects. Installing can only fail if a
/// subscriber is already set, which nothing in this binary does.
fn install_logging(verbose: u8) {
    let level = rotate::redact::level_for(verbose);
    let _ =
        tracing::subscriber::set_global_default(rotate::redact::subscriber(level, std::io::stderr));
}

/// `config` with `--allow-broader-replacement` (SHA-291) applied: the flag
/// turns `providers.openai.allow_broader_replacement` on for this run and
/// never off.
fn opt_in(config: &Config, allow_broader_replacement: bool) -> Config {
    let mut config = config.clone();
    config.providers.openai.allow_broader_replacement |= allow_broader_replacement;
    config
}

/// Runs one subcommand. Errors are printed, redacted, by `main` with exit 1.
fn run(
    console: &mut Console,
    command: Command,
    config: &Config,
    json: bool,
) -> Result<Exit, rotate::error::Error> {
    if let (Command::Apply(_) | Command::Rollback(_), true) = (&command, json) {
        let _ = writeln!(
            console.err(),
            "error: rotate {} does not support --json yet",
            command.name()
        );
        return Ok(Exit::Usage);
    }
    if let Some(input) = command.input() {
        let findings = match read_input(console, input) {
            Ok(findings) => findings,
            Err(exit) => return Ok(exit),
        };
        #[cfg(feature = "leak-canary-test")]
        plant_leak(&findings);
        match &command {
            Command::Plan(args) => {
                let check = args.check_permissions;
                let config = &opt_in(config, args.allow_broader_replacement);
                return Ok(plan(console, findings, input, config, json, check));
            }
            Command::Apply(args) => {
                let config = &opt_in(config, args.allow_broader_replacement);
                return Ok(apply(console, findings, args, config));
            }
            Command::Rollback(args) => return Ok(rollback(console, findings, args, config)),
            _ => {}
        }
    }
    match &command {
        Command::Status(args) => Ok(status(console, args, config, json)),
        other => {
            let _ = writeln!(console.err(), "rotate {}: not implemented", other.name());
            Ok(Exit::Usage)
        }
    }
}

/// `rotate status` (SHA-263): reads the state file without taking its lock
/// and the audit log read-only, and prints one row per rotation in
/// progress (every rotation with `--all`). It builds no provider or
/// consumer registry and starts no runtime, so it cannot make a call, and
/// it writes nothing. Exit 3 when any rotation is pending, else 0; an
/// unusable state file exits 2 (1 for a plain I/O error). An unusable
/// audit log is a warning: the rows are shown without its errors.
fn status(console: &mut Console, args: &StatusArgs, config: &Config, json: bool) -> Exit {
    let snapshot = match StateStore::read(&config.state_file) {
        Ok(snapshot) => snapshot,
        Err(err) => return state_error(console, err),
    };
    let (errors, warnings) = match rotate::audit::read_all(&config.audit_log) {
        Ok(entries) => rotate::status::last_errors(entries),
        Err(err) => (
            Default::default(),
            vec![format!("audit log errors are not shown: {err}")],
        ),
    };
    for warning in &warnings {
        let _ = writeln!(console.err(), "warning: {warning}");
    }
    let now = providers::clock().map_or_else(time::OffsetDateTime::now_utc, |clock| clock());
    let rows = rotate::status::rows(&snapshot, &errors, now, args.all);
    let rendered = if json {
        rotate::status::render_json(&rows) + "\n"
    } else {
        rotate::status::render_table(&rows, snapshot.rotations().len(), now)
    };
    print_out(console, &rendered);
    if rotate::status::any_pending(&snapshot) {
        Exit::Pending
    } else {
        Exit::Ok
    }
}

/// A single-threaded runtime for the provider and consumer calls. The real
/// plugins' HTTP clients (AWS SDK, reqwest) need the IO driver as well as
/// timers, so every driver is enabled.
fn runtime(console: &mut Console) -> Result<tokio::runtime::Runtime, Exit> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            let _ = writeln!(
                console.err(),
                "error: could not start the async runtime: {err}"
            );
            Exit::RotationFailed
        })
}

/// Assesses `findings`, builds the plan and gives every rotation its id in
/// `store`. Only read-only remote calls are made (SHA-250). Findings whose
/// secret was already rotated are skipped first, with no call at all
/// (SHA-258).
fn build_plan(
    console: &mut Console,
    runtime: &tokio::runtime::Runtime,
    findings: Vec<Finding>,
    input: &InputArgs,
    config: &Config,
    registries: (&ProviderRegistry, &ConsumerRegistry),
    store: &mut StateStore,
) -> Result<plan::Plan, Exit> {
    let (registry, consumers) = registries;
    let opts = AssessOptions {
        concurrency: usize::from(input.concurrency),
        force_provider: input
            .provider
            .as_deref()
            .and_then(|name| registry.get(name))
            .map(|provider| provider.name()),
        ..AssessOptions::default()
    };
    let (findings, already_rotated) =
        plan::split_already_rotated(findings, store.rotations(), registry);
    let mut plan = runtime.block_on(async {
        let assessed = assess(findings, registry, &opts).await;
        plan::build(
            assessed,
            registry,
            consumers,
            config.overlap_window,
            &config.consumers,
        )
        .await
    });
    plan.skipped.extend(already_rotated);
    // SHA-287: plan and apply both show where secrets are being sent.
    plan.warnings = config.providers.endpoint_warnings();
    plan::mark_revoked_by_hand(&mut plan, store.rotations());
    if let Err(err) = plan::assign_ids(&mut plan, store) {
        return Err(state_error(console, err));
    }
    Ok(plan)
}

/// Builds the plan (SHA-250) and prints the table or JSON: assessment
/// (SHA-248), then `find` on every consumer, then a `planned` record per new
/// rotation in the state file. No state-changing remote call is made.
/// Blockers and skipped rows are information, not failures: exit 0. A held
/// or unusable state file exits 2 before any provider call; a plain I/O
/// error writing it exits 1. With `check_permissions`, read-only permission
/// probes (SHA-270) add blockers and not-updatable reasons to the plan and
/// print a warning for each probe that could not run.
fn plan(
    console: &mut Console,
    findings: Vec<Finding>,
    input: &InputArgs,
    config: &Config,
    json: bool,
    check_permissions: bool,
) -> Exit {
    let mut store = match StateStore::open(&config.state_file) {
        Ok(store) => store,
        Err(err) => return state_error(console, err),
    };
    let registry = providers::registry_with(&config.providers);
    let consumers = providers::consumers_with(
        &config.consumers,
        &config.providers.github,
        &config.providers.aws,
    );
    let runtime = match runtime(console) {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let mut plan = match build_plan(
        console,
        &runtime,
        findings,
        input,
        config,
        (&registry, &consumers),
        &mut store,
    ) {
        Ok(plan) => plan,
        Err(exit) => return exit,
    };
    drop(store);
    if check_permissions {
        match providers::permission_checker(config) {
            Some(checker) => {
                for warning in runtime.block_on(checker.check(&mut plan)) {
                    let _ = writeln!(console.err(), "warning: {warning}");
                }
            }
            None => {
                let _ = writeln!(
                    console.err(),
                    "warning: permissions not checked: no real plugins in this build"
                );
            }
        }
    }
    let rendered = if json {
        plan::render_json(&plan) + "\n"
    } else {
        plan::render_table(&plan)
    };
    print_out(console, &rendered);
    Exit::Ok
}

/// `rotate apply` (SHA-254): re-plans from the same input, prints the plan,
/// asks for confirmation (or takes `--confirm`), then runs the confirmed
/// rotations through the executor: create, update consumers and verify for
/// each, then the revokes, last, batched per provider (SHA-286).
/// The state lock is held for the whole run. Nothing state-changing happens
/// before every confirmation is in and the audit log is open. The plan, and
/// with it every credential, lives until the summary is printed, so the
/// values stay registered with the redactor for every message.
///
/// A replacement supplied with `--replacement-from-env` or
/// `--replacement-file` (SHA-257) is read first, before the state file or
/// any provider call, so a refusal exits 2 having touched nothing.
fn apply(console: &mut Console, findings: Vec<Finding>, args: &ApplyArgs, config: &Config) -> Exit {
    let mut supplied = match supplied_replacement(args) {
        Ok(supplied) => supplied,
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            return Exit::Usage;
        }
    };
    let mut store = match StateStore::open(&config.state_file) {
        Ok(store) => store,
        Err(err) => return state_error(console, err),
    };
    let registry = providers::registry_with(&config.providers);
    let consumers = providers::consumers_with(
        &config.consumers,
        &config.providers.github,
        &config.providers.aws,
    );
    let runtime = match runtime(console) {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let plan = match build_plan(
        console,
        &runtime,
        findings,
        &args.input,
        config,
        (&registry, &consumers),
        &mut store,
    ) {
        Ok(plan) => plan,
        Err(exit) => return exit,
    };
    print_out(console, &plan::render_apply_table(&plan));
    // Old secrets deleted by hand since an earlier run (SHA-289): recorded
    // revoked with no further call and no question.
    let by_hand: Vec<&plan::Skipped> = plan
        .skipped
        .iter()
        .filter(|s| s.reason == plan::REVOKED_BY_HAND)
        .collect();
    if plan.rotations.is_empty() && by_hand.is_empty() {
        let _ = writeln!(console.err(), "Nothing to apply.");
        return Exit::Ok;
    }

    // A --confirm naming a rotation deleted by hand is not an unknown id.
    let mut all_ids = apply::rotation_ids(&plan);
    all_ids.extend(by_hand.iter().filter_map(|s| s.rotation_id.as_deref()));
    let mut askable = Vec::new();
    for rotation in &plan.rotations {
        match apply::eligibility_in(rotation, &store) {
            Ok(()) => askable.push(rotation.rotation_id.as_str()),
            Err(why) => {
                let _ = writeln!(
                    console.err(),
                    "note: rotation {} will be skipped: {why}",
                    rotation.rotation_id
                );
            }
        }
    }
    let request = if !args.confirm.is_empty() {
        Confirmation::Ids(args.confirm.clone())
    } else if args.all {
        Confirmation::All
    } else {
        Confirmation::Interactive
    };
    let mut prompt = providers::prompt().unwrap_or_else(|| Box::new(TtyPrompt::new()));
    let confirmed = {
        // Each question is written before its answer is read.
        let mut err = QuestionWriter::new(&mut *console);
        let result = apply::confirm(&all_ids, &askable, &request, prompt.as_mut(), &mut err);
        drop(err);
        match result {
            Ok(confirmed) => confirmed,
            Err(err) => {
                let _ = writeln!(console.err(), "error: {err}");
                return Exit::Usage;
            }
        }
    };
    // With --confirm only the named rotations count; otherwise every
    // rotation in the plan does, including those skipped as unsupported.
    let requested: Vec<&plan::PlannedRotation> = plan
        .rotations
        .iter()
        .filter(|r| match request {
            Confirmation::Ids(_) => confirmed.contains(&r.rotation_id),
            _ => confirmed.contains(&r.rotation_id) || apply::eligibility_in(r, &store).is_err(),
        })
        .collect();

    // A supplied replacement is one value: it can serve one manual rotation.
    let manual = requested
        .iter()
        .filter(|r| {
            r.replacement_mode == ReplacementMode::Manual
                && apply::eligibility_in(r, &store).is_ok()
        })
        .count();
    if supplied.is_some() {
        if manual > 1 {
            let _ = writeln!(
                console.err(),
                "error: --replacement-from-env and --replacement-file supply one replacement, but {manual} manual rotations are confirmed; confirm one at a time with --confirm <rotation-id>. Nothing was changed."
            );
            return Exit::Usage;
        }
        if manual == 0 {
            let _ = writeln!(
                console.err(),
                "note: no confirmed rotation is in manual replacement mode; the supplied replacement is not used"
            );
            supplied = None;
        }
    }

    let mut outcomes = Vec::new();
    if !by_hand.is_empty()
        || requested
            .iter()
            .any(|r| apply::eligibility_in(r, &store).is_ok())
    {
        let mut audit = match AuditLog::open(&config.audit_log) {
            Ok(audit) => audit,
            Err(err) => {
                let _ = writeln!(console.err(), "error: {err}");
                return if err.is_usage() {
                    Exit::Usage
                } else {
                    Exit::RotationFailed
                };
            }
        };
        let source = match supplied.take() {
            Some(value) => ReplacementSource::Supplied(Some(value)),
            None => ReplacementSource::Prompt(prompt),
        };
        let mut executor = Executor::new(&registry, &consumers, &mut store, &mut audit)
            .with_force(args.force)
            .with_wait(args.wait)
            .with_manual(source, &mut *console);
        if let Some(clock) = providers::clock() {
            executor = executor.with_clock(clock);
        }
        outcomes.extend(
            by_hand
                .iter()
                .filter_map(|s| executor.confirm_revoked_by_hand(s)),
        );
        outcomes.extend(runtime.block_on(executor.run_all(&requested)));
    } else {
        outcomes.extend(requested.iter().filter_map(|r| {
            apply::eligibility_in(r, &store)
                .err()
                .map(|why| apply::Outcome::skipped(r, why))
        }));
    }
    drop(store);
    print_out(console, &format!("\n{}", apply::render_summary(&outcomes)));
    match apply::run_status(&outcomes) {
        RunStatus::Done => Exit::Ok,
        RunStatus::Failed => Exit::RotationFailed,
        RunStatus::RevokeManual => Exit::RevokeManual,
        RunStatus::Pending => Exit::Pending,
        RunStatus::Unsupported => Exit::Usage,
    }
}

/// `rotate rollback` (SHA-259): matches the input secrets to rotations in
/// the state file by fingerprint, prints the rollback plan, asks for
/// confirmation (or takes `--confirm`), then for each confirmed rotation
/// restores the old secret at the provider, restores every updated
/// consumer and revokes the replacement. The state lock is held for the
/// whole run. Nothing is called before the match and every confirmation;
/// no match exits 2 having made no call. The input credentials live until
/// the summary is printed, so they stay registered with the redactor.
fn rollback(
    console: &mut Console,
    findings: Vec<Finding>,
    args: &RollbackArgs,
    config: &Config,
) -> Exit {
    let inputs = rollback::inputs(findings);
    let mut store = match StateStore::open(&config.state_file) {
        Ok(store) => store,
        Err(err) => return state_error(console, err),
    };
    let selected = match rollback::select(store.rotations(), &inputs, args.rotation.as_deref()) {
        Ok(selected) => selected,
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            return Exit::Usage;
        }
    };
    let plans: Vec<(rollback::RollbackPlan, usize)> = selected
        .iter()
        .map(|s| (rollback::RollbackPlan::of(&s.rotation), s.input))
        .collect();
    let all: Vec<rollback::RollbackPlan> = plans.iter().map(|(p, _)| p.clone()).collect();
    print_out(console, &rollback::render_plan(&all));
    let ids: Vec<&str> = plans
        .iter()
        .filter(|(p, _)| p.has_work())
        .map(|(p, _)| p.rotation_id.as_str())
        .collect();
    if ids.is_empty() {
        let _ = writeln!(console.err(), "Nothing to roll back.");
        return Exit::Ok;
    }

    let request = if args.confirm.is_empty() {
        Confirmation::Interactive
    } else {
        Confirmation::Ids(args.confirm.clone())
    };
    let mut prompt = providers::prompt().unwrap_or_else(|| Box::new(TtyPrompt::new()));
    let confirmed = {
        let mut err = QuestionWriter::new(&mut *console);
        let result = apply::confirm(&ids, &ids, &request, prompt.as_mut(), &mut err);
        drop(err);
        match result {
            Ok(confirmed) => confirmed,
            Err(err) => {
                let _ = writeln!(console.err(), "error: {err}");
                return Exit::Usage;
            }
        }
    };
    if confirmed.is_empty() {
        let _ = writeln!(console.err(), "Nothing was confirmed; nothing was changed.");
        return Exit::Ok;
    }

    let mut audit = match AuditLog::open(&config.audit_log) {
        Ok(audit) => audit,
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            return if err.is_usage() {
                Exit::Usage
            } else {
                Exit::RotationFailed
            };
        }
    };
    let registry = providers::registry_with(&config.providers);
    let consumers = providers::consumers_with(
        &config.consumers,
        &config.providers.github,
        &config.providers.aws,
    );
    let runtime = match runtime(console) {
        Ok(runtime) => runtime,
        Err(exit) => return exit,
    };
    let mut outcomes = Vec::new();
    {
        let mut executor =
            rollback::RollbackExecutor::new(&registry, &consumers, &mut store, &mut audit);
        runtime.block_on(async {
            for (plan, input) in &plans {
                if confirmed.contains(&plan.rotation_id) {
                    outcomes.push(executor.run(plan, &inputs[*input].credential).await);
                }
            }
        });
    }
    drop(store);
    for outcome in &outcomes {
        for warning in outcome.stderr_warnings() {
            let _ = writeln!(console.err(), "warning: {}: {warning}", outcome.rotation_id);
        }
    }
    print_out(
        console,
        &format!("\n{}", rollback::render_summary(&outcomes)),
    );
    if rollback::needs_operator(&outcomes) {
        Exit::RotationFailed
    } else {
        Exit::Ok
    }
}

/// The replacement named by `--replacement-from-env` or
/// `--replacement-file`, if either was given. Errors name neither the
/// variable nor the path.
fn supplied_replacement(
    args: &ApplyArgs,
) -> Result<Option<SecretValue>, rotate::input::ReplacementInputError> {
    if let Some(name) = &args.replacement_from_env {
        return rotate::input::replacement_from_env(name).map(Some);
    }
    if let Some(path) = &args.replacement_file {
        return rotate::input::replacement_from_file(path).map(Some);
    }
    Ok(None)
}

/// Reports a state-store error: exit 2 for a held lock or an unusable file
/// (the operator must act), exit 1 for a plain I/O failure.
fn state_error(console: &mut Console, err: StateError) -> Exit {
    let _ = writeln!(console.err(), "error: {err}");
    if err.is_usage() {
        Exit::Usage
    } else {
        Exit::RotationFailed
    }
}

/// The single stdout print site for command output (plan table or JSON):
/// one redacted write of the whole rendering.
fn print_out(console: &mut Console, text: &str) {
    let _ = console.out().write_all(text.as_bytes());
}

/// Reads the findings named by `input` (SHA-247). Errors are printed here
/// and never include what was read or a path the operator typed: a secret
/// pasted where the report path goes must not be echoed back.
fn read_input(console: &mut Console, input: &InputArgs) -> Result<Vec<Finding>, Exit> {
    if input.provider.is_some() {
        let registry = providers::registry();
        let known = registry.names();
        if !input
            .provider
            .as_deref()
            .is_some_and(|name| known.contains(&name))
        {
            let known = if known.is_empty() {
                "none are built in yet".to_owned()
            } else {
                known.join(", ")
            };
            let _ = writeln!(
                console.err(),
                "error: unknown provider; known providers: {known}"
            );
            return Err(Exit::Usage);
        }
    }

    if input.stdin {
        let stdin = std::io::stdin();
        // The hint is best effort; a closed stderr must not stop the read.
        let _ = rotate::input::stdin_hint(stdin.is_terminal(), &mut console.err());
        return match rotate::input::read_secret(stdin.lock()) {
            Ok(finding) => Ok(vec![finding]),
            Err(err) => {
                let _ = writeln!(console.err(), "error: {err}");
                Err(Exit::Usage)
            }
        };
    }

    let Some(path) = &input.report else {
        let _ = writeln!(
            console.err(),
            "error: no input: pass a report path or --stdin"
        );
        return Err(Exit::Usage);
    };
    match read_report(path, input.format) {
        Ok(report) => {
            for warning in &report.warnings {
                let _ = writeln!(console.err(), "warning: {warning}");
            }
            Ok(report.findings)
        }
        Err(ReportError::Io { source, .. }) => {
            let usage = Cli::command().render_usage();
            let _ = writeln!(
                console.err(),
                "error: could not read the report file ({}). Secrets must be passed with --stdin, never as an argument.\n\n{usage}",
                source.kind()
            );
            Err(Exit::Usage)
        }
        Err(err) => {
            let _ = writeln!(console.err(), "error: {err}");
            Err(Exit::Usage)
        }
    }
}

/// The hidden `__test-console` subcommand (`test-commands` feature only).
/// `secret` was read from stdin, so it is registered with the redactor as
/// real input is. It goes down the output path `mode` names, and is also
/// logged at error level so tests can check the tracing path.
#[cfg(feature = "test-commands")]
fn test_console(
    console: &mut Console,
    mode: cli::TestConsoleMode,
    secret: &rotate::secret::SecretValue,
) -> Result<Exit, rotate::error::Error> {
    use cli::TestConsoleMode;
    use rotate::provider::ProviderError;

    let value = secret
        .expose_secret_str(str::to_owned)
        .map_err(rotate::error::Error::new)?;
    tracing::error!("test-console saw {value}");
    match mode {
        TestConsoleMode::Out => {
            let _ = writeln!(console.out(), "value: {value}");
            Ok(Exit::Ok)
        }
        TestConsoleMode::Error => {
            Err(ProviderError::Permanent(format!("provider rejected {value}")).into())
        }
        TestConsoleMode::Panic => panic!("test-console panic with {value}"),
        TestConsoleMode::Json => {
            let doc = serde_json::json!({
                "rotations": [{
                    "fingerprint": secret.fingerprint().to_string(),
                    "note": format!("upstream echoed {value}"),
                    "values": [value.clone(), { "nested": value }],
                }],
            });
            print_out(console, &(doc.to_string() + "\n"));
            Ok(Exit::Ok)
        }
    }
}

/// The deliberate leak of the `leak-canary-test` feature (SHA-265): when
/// `ROTATE_TEST_PLANT_LEAK` is `stdout`, `stderr` or a relative file name,
/// writes the first input secret there once, raw, past the console's
/// redaction. `tests/leakage.rs` uses it to prove its sweep fails on a leak.
#[cfg(feature = "leak-canary-test")]
fn plant_leak(findings: &[Finding]) {
    let Some(target) = std::env::var_os("ROTATE_TEST_PLANT_LEAK") else {
        return;
    };
    let Some(finding) = findings.first() else {
        return;
    };
    let mut bytes = finding.raw.expose_secret(<[u8]>::to_vec);
    bytes.push(b'\n');
    let _ = match target.to_str() {
        Some("stdout") => std::io::stdout().write_all(&bytes),
        Some("stderr") => std::io::stderr().write_all(&bytes),
        _ => std::fs::write(&target, &bytes),
    };
}
