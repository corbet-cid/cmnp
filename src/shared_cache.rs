//! One shared result transaction around moon's native lookup/hydration/execution.
use super::*;
use crate::{content_key, inputs};
use std::{
    fs::{File, OpenOptions, TryLockError},
    sync::atomic::Ordering,
    thread,
};

fn workspace_lock(root: &Path, deadline: Instant) -> Result<File> {
    fs::create_dir_all(root.join(".ccid"))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".ccid/executor.lock"))?;
    loop {
        if crate::INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(failure("Workspace cache lock timed out or interrupted"));
        }
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(20)),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
    }
}

fn share_artifacts(root: &Path, shared: &Path) -> Result<()> {
    fs::create_dir_all(root.join(".moon/cache"))?;
    for name in ["hashes", "outputs"] {
        let source = shared.join("moon").join(name);
        fs::create_dir_all(&source)?;
        let target = root.join(".moon/cache").join(name);
        if fs::symlink_metadata(&target).is_ok() {
            if target.canonicalize()? != source.canonicalize()? {
                // Nothing has started: the caller degrades to an uncached check.
                return Err(crate::content_key::refusal(
                    "Moon artifact cache belongs to a different coordinator",
                ));
            }
        } else {
            #[cfg(unix)]
            std::os::unix::fs::symlink(source, target)?;
            #[cfg(not(unix))]
            return Err(failure("Shared result caching requires Unix"));
        }
    }
    Ok(())
}

fn output_digest(root: &Path, names: &[String]) -> Result<String> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<String, String>) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if meta.is_symlink() {
            return Err(failure("Cached output symlinks are unsupported"));
        }
        let name = path
            .strip_prefix(root)?
            .to_str()
            .ok_or_else(|| failure("Output path requires UTF-8"))?
            .to_owned();
        if meta.is_dir() {
            entries.insert(name, "directory".into());
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), entries)?;
            }
        } else if meta.is_file() {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111
            };
            #[cfg(not(unix))]
            let mode = 0;
            entries.insert(name, format!("{mode}:{}", inputs::file_digest(path)?));
        } else {
            return Err(failure("Cached output is not a regular artifact"));
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    for name in names {
        visit(root, &root.join(name), &mut entries)?;
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&entries)?)
    ))
}

fn report(root: &Path, target: &str) -> Result<(String, String)> {
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".moon/cache/runReport.json"))?)?;
    parse_report(&report, target)
}

fn parse_report(report: &serde_json::Value, target: &str) -> Result<(String, String)> {
    let state = &report["context"]["targetStates"][target];
    // Target state records success even on hydration. The action status, not
    // target state or replayed stdout, distinguishes execution from a cache hit.
    let actions: Vec<_> = report["actions"]
        .as_array()
        .ok_or_else(|| failure("Moon report lacks actions"))?
        .iter()
        .filter(|a| a["node"]["action"] == "run-task" && a["node"]["params"]["target"] == target)
        .collect();
    if actions.len() != 1 {
        return Err(failure(
            "Moon report must contain exactly one selected task action",
        ));
    }
    let status = actions[0]["status"]
        .as_str()
        .ok_or_else(|| failure("Moon report lacks task action status"))?;
    if !["passed", "cached", "cached-from-remote"].contains(&status) {
        return Err(failure(format!("Moon target did not succeed: {status}")));
    }
    let hash = state["hash"]
        .as_str()
        .ok_or_else(|| failure("Moon report lacks task hash"))?;
    content_key::validate_key_hex(hash)?;
    Ok((status.into(), hash.into()))
}

/// Every input of one check's result key, assembled in one place so that its
/// completeness is testable: source tree, dependency lock, effective command,
/// tool identity (toolchain, runner configuration, executables), moon, platform,
/// semantic environment and the check declaration. Nothing here names a path,
/// URL, commit or run.
pub(super) fn key_inputs(
    request: &Request,
    check: &Check,
    name: &str,
    root: &Path,
    source: String,
    identity: String,
    moon: String,
) -> Result<content_key::ContentKeyInputs> {
    let mut outputs = check.cache_outputs.clone();
    outputs.push(format!("{RESULTS}/{name}.jsonl"));
    Ok(content_key::ContentKeyInputs {
        schema: content_key::SCHEMA,
        kind: check.kind.clone(),
        input_digest: source,
        lock_digest: inputs::lock_digest(root, check)?,
        commands: vec![vec![
            request.tool.clone(),
            "check".into(),
            "--repo".into(),
            ".".into(),
            "--manifest".into(),
            request.manifest_arg.clone(),
            "--check".into(),
            name.to_owned(),
        ]],
        tool_digests: BTreeMap::from([("executor".into(), identity), ("moon".into(), moon)]),
        platform_abi: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        env: inputs::semantic_environment(check, &request.environment),
        check_config: serde_json::to_value(check)?,
        outputs,
    })
}

pub(super) fn execute(request: &Request, prepared: CachePreflight) -> Result<()> {
    if request.force {
        return Err(failure(
            "Shared result caching cannot force recomputation; use an explicit uncached check",
        ));
    }
    let started = Instant::now();
    let timeout = value(&request.environment, "CI_TIMEOUT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2700);
    let deadline = started
        .checked_add(Duration::from_secs(timeout))
        .ok_or_else(|| failure("Cache deadline overflow"))?;
    let root = request.repo.canonicalize()?;
    let shared = content_key::validate_root(Path::new(
        &value(&request.environment, "CCID_RESULT_CACHE")
            .ok_or_else(|| failure("Shared caching requires provisioned CCID_RESULT_CACHE"))?,
    ))?;
    let _workspace = workspace_lock(&root, deadline)?;
    let probe = Runner::new(
        root.clone(),
        request.environment.clone(),
        deadline.saturating_duration_since(Instant::now()),
    )?;
    if !supported_moon(&prepared.moon_version) {
        return Err(failure("Shared cache layout requires moon 2.4.6 or 2.5.x"));
    }
    share_artifacts(&root, &shared)?;
    let mut probes = BTreeMap::new();
    let mut measurements = Vec::new();
    for name in &request.selected {
        let check = &request.checks[name];
        if check.cache == Some(false) || check.cache_commit {
            return Err(failure("Check is explicitly non-cacheable"));
        }
        if let Some(reason) = check.uncached_reason(&root) {
            return Err(failure(format!(
                "Check cannot use shared results: {reason}"
            )));
        }
        if check.kind == "nix"
            && (!root.join(".git").exists()
                || !probe
                    .run(
                        &argv(&["git", "status", "--porcelain", "--untracked-files=no"]),
                        true,
                    )?
                    .is_empty())
        {
            return Err(failure("Nix cache requires a committed clean flake"));
        }
        let source = inputs::source_digest(&root, check, &request.environment)?;
        let receipt = format!("{RESULTS}/{name}.jsonl");
        let mut outputs = check.cache_outputs.clone();
        outputs.push(receipt.clone());
        let key = key_inputs(
            request,
            check,
            name,
            &root,
            source.clone(),
            prepared.identity.clone(),
            inputs::tool_digest("moon", &probe, &mut probes)?,
        )?
        .key_hex()?;
        let waiting = Instant::now();
        let mut guard = content_key::acquire(
            &shared,
            &key,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        let waited = waiting.elapsed().as_secs_f64();
        let prior = guard.observed_success().and_then(|s| s.producer.clone());
        let mut env = inputs::execution_environment(check, &request.environment);
        // This flag is not a key input: it only refuses a fallback execution
        // when native hydration of a previously completed key is unavailable.
        if prior.is_some() {
            env.insert("CCID_CACHE_REPLAY_ONLY".into(), "1".into());
        }
        if let Some(url) = remote_cache(&env)? {
            env.insert("MOON_REMOTE_HOST".into(), url.clone().into());
            env.insert(
                "MOON_REMOTE_API".into(),
                if url.starts_with("http") {
                    "http"
                } else {
                    "grpc"
                }
                .into(),
            );
            env.insert("MOON_REMOTE_CACHE_COMPRESSION".into(), "zstd".into());
        }
        write_generated(
            &root.join(".moon/workspace.yml"),
            &render_workspace(&request.project),
        )?;
        write_generated(
            &root.join("moon.yml"),
            &render_tasks(
                &BTreeMap::from([(name.clone(), check.clone())]),
                std::slice::from_ref(name),
                &request.manifest_arg,
                &request.tool,
                &BTreeMap::from([(name.clone(), key.clone())]),
            ),
        )?;
        fs::create_dir_all(root.join(RESULTS))?;
        for generated in [root.join(&receipt), root.join(".moon/cache/runReport.json")] {
            if generated.is_file() {
                fs::remove_file(generated)?;
            }
        }
        // A native cache transaction may hydrate rather than compute. The
        // ledger records attempts; the native report measures computations.
        if prior.is_none() {
            guard.begin_compute()?;
        }
        let timer = tempfile::NamedTempFile::new_in(root.join(".ccid"))?;
        let mut command = vec![
            "moon".into(),
            "run".into(),
            format!("{}:{name}", request.project),
        ];
        let timed = value(&env, "CMNP_TIME");
        if let Some(time) = &timed {
            let mut wrapper = vec![
                time.clone(),
                "-f".into(),
                "{\"user\":%U,\"system\":%S}".into(),
                "-o".into(),
                timer.path().to_string_lossy().into_owned(),
                "--".into(),
            ];
            wrapper.extend(command);
            command = wrapper;
        }
        let run = Runner::new(
            root.clone(),
            env,
            deadline.saturating_duration_since(Instant::now()),
        )?
        .run(&command, false);
        let cpu: Option<serde_json::Value> = if timed.is_some() {
            fs::read(timer.path())
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
        } else {
            None
        };
        // The runner reaped the check's process group on exit or terminated it
        // on deadline and interruption, so a failed run is a final Failed
        // attempt: never reused, and the next identical request computes again.
        // Only a hard kill of this process leaves a Running record behind.
        if let Err(error) = run {
            event(
                json!({"event":"cache-check","check":name,"key":key,"status":"failed","cpu_seconds":cpu,"wait_seconds":waited,"duplicate_computations":null}),
            );
            let _ = guard.publish_failure(None);
            return Err(error);
        }
        let (status, moon_hash) = report(&root, &format!("{}:{name}", request.project))?;
        let computed = u64::from(status == "passed");
        let duplicates = u64::from(prior.is_some()) * computed;
        if duplicates != 0 {
            return Err(failure(
                "Duplicate computation detected despite replay guard",
            ));
        }
        if inputs::source_digest(&root, check, &request.environment)? != source {
            // Publication is optional: the check itself passed, so its result
            // stands, but a run that rewrote its own declared inputs is never
            // reusable. Record a Failed attempt and carry on without the cache.
            event(
                json!({"event":"cache-publication-skipped","check":name,"key":key,"reason":"check mutated its declared source inputs"}),
            );
            let _ = guard.publish_failure(None);
            let record = json!({"event":"cache-check","check":name,"key":key,"native_hash":moon_hash,"status":status,"computed":computed,"duplicate_computations":duplicates,"wait_seconds":waited,"cpu_seconds":cpu,"published":false});
            event(record.clone());
            measurements.push(record);
            continue;
        }
        let output = output_digest(&root, &outputs)?;
        if let Some(expected) = &prior {
            let producer: serde_json::Value = serde_json::from_str(expected)?;
            if producer["outputs"] != output || producer["moon_hash"] != moon_hash {
                return Err(failure(
                    "Restored artifact digest or native task hash differs from completed result",
                ));
            }
        } else {
            guard.publish_success(Some(
                json!({"outputs":output,"moon_hash":moon_hash,"computed":computed}).to_string(),
            ))?;
        }
        let record = json!({"event":"cache-check","check":name,"key":key,"native_hash":moon_hash,"status":status,"computed":computed,"duplicate_computations":duplicates,"wait_seconds":waited,"cpu_seconds":cpu});
        event(record.clone());
        measurements.push(record);
    }
    let hits = measurements.iter().filter(|r| r["computed"] == 0).count();
    let summary = json!({"event":"cache-run","checks":measurements,"result":{"hits":hits,"requests":request.selected.len(),"hit_rate":hits as f64 / request.selected.len().max(1) as f64},"compile":null,"nix_eval":null,"fetch":null,"seconds":started.elapsed().as_secs_f64()});
    fs::write(
        root.join(".ccid/cache-metrics.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    event(summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn foreign_moon_cache_is_a_typed_refusal_not_a_hard_failure() {
        let root = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".moon/cache")).unwrap();
        std::os::unix::fs::symlink(foreign.path(), root.path().join(".moon/cache/hashes")).unwrap();
        let error = share_artifacts(root.path(), shared.path()).unwrap_err();
        assert!(error
            .downcast_ref::<crate::content_key::LedgerRefusal>()
            .is_some());
    }

    #[test]
    fn cached_action_with_passed_target_did_not_compute() {
        let hash = "a".repeat(64);
        let mut report = json!({"context":{"targetStates":{"p:test":{"state":"passed","hash":hash}}},"actions":[{"node":{"action":"run-task","params":{"target":"p:test"}},"status":"cached"}]});
        for status in ["cached", "cached-from-remote", "passed"] {
            report["actions"][0]["status"] = json!(status);
            assert_eq!(parse_report(&report, "p:test").unwrap().0, status);
        }
    }

    // ---- Key completeness: every input of a deterministic check changes the
    // key, and nothing about location, provenance or the URL does. ----

    fn tools_dir(version: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("mytool");
        fs::write(&tool, format!("#!/bin/sh\necho {version}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        // Equal modification times keep identical tool directories identical.
        let stamp = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        File::options()
            .write(true)
            .open(&tool)
            .unwrap()
            .set_modified(stamp)
            .unwrap();
        dir
    }
    fn source(files: &[(&str, &str)]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let path = root.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        root
    }
    fn base_check() -> Check {
        Check {
            kind: "commands".into(),
            commands: vec![vec!["mytool".into(), "--run".into()]],
            ..Check::default()
        }
    }
    fn environment(tools: &Path) -> Environment {
        let mut paths = vec![tools.to_path_buf()];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let mut env = Environment::new();
        env.insert("PATH".into(), std::env::join_paths(paths).unwrap());
        env
    }
    /// The complete result key of one check, exactly as `execute` assembles it.
    fn key(root: &Path, check: &Check, env: &Environment) -> String {
        let request = Request {
            repo: root.into(),
            project: "project".into(),
            manifest_arg: ".ci/ccid.toml".into(),
            checks: BTreeMap::from([("t".into(), check.clone())]),
            selected: vec!["t".into()],
            plan: false,
            force: false,
            tool: "ccid".into(),
            tool_revision: "revision".into(),
            environment: env.clone(),
        };
        let runner = Runner::new(root.into(), env.clone(), Duration::from_secs(20)).unwrap();
        let executor = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let identity = tool_identity(
            &runner,
            check,
            env,
            &executor,
            "revision",
            &mut BTreeMap::new(),
        )
        .unwrap();
        let source = inputs::source_digest(root, check, env).unwrap();
        key_inputs(&request, check, "t", root, source, identity, "a".repeat(64))
            .unwrap()
            .key_hex()
            .unwrap()
    }

    #[test]
    fn a_default_commands_check_is_pure_and_keyable_without_declarations() {
        let check = base_check();
        assert!(check.is_pure() && check.cache_tools.is_empty() && check.cache_inputs.is_none());
        let root = source(&[("src/main.txt", "one"), (".ci/ccid.toml", "schema = 1")]);
        let tools = tools_dir("v1");
        assert_eq!(
            key(root.path(), &check, &environment(tools.path())).len(),
            64
        );
    }

    #[test]
    fn every_input_of_a_deterministic_check_changes_the_key() {
        let tools = tools_dir("v1");
        let env = environment(tools.path());
        let files = [
            ("src/main.txt", "one"),
            ("Cargo.lock", "# lock a"),
            (".ci/ccid.toml", "schema = 1"),
        ];
        let root = source(&files);
        let check = base_check();
        let baseline = key(root.path(), &check, &env);
        assert_eq!(
            key(root.path(), &check, &env),
            baseline,
            "key must be stable"
        );
        let mut seen = std::collections::BTreeSet::from([baseline.clone()]);
        let mut distinct = |label: &str, value: String| {
            assert!(seen.insert(value), "{label} did not change the key");
        };

        // Source tree: edit, add an untracked file, delete.
        let edited = source(&files);
        fs::write(edited.path().join("src/main.txt"), "two").unwrap();
        distinct("edited file", key(edited.path(), &check, &env));
        let added = source(&files);
        fs::write(added.path().join("src/new.txt"), "x").unwrap();
        distinct("added file", key(added.path(), &check, &env));
        let removed = source(&files);
        fs::remove_file(removed.path().join("src/main.txt")).unwrap();
        distinct("removed file", key(removed.path(), &check, &env));
        // Dependency lock.
        let locked = source(&files);
        fs::write(locked.path().join("Cargo.lock"), "# lock b").unwrap();
        distinct("lock", key(locked.path(), &check, &env));
        // Check declaration: command line, features, packages, flags, toolchain.
        for (label, change) in [
            (
                "command",
                Box::new(|c: &mut Check| c.commands[0].push("--more".into()))
                    as Box<dyn Fn(&mut Check)>,
            ),
            (
                "features",
                Box::new(|c: &mut Check| c.features = vec!["tls".into()]),
            ),
            (
                "packages",
                Box::new(|c: &mut Check| c.packages = vec!["core".into()]),
            ),
            (
                "all_features",
                Box::new(|c: &mut Check| c.all_features = true),
            ),
            ("release", Box::new(|c: &mut Check| c.release = true)),
            (
                "actions",
                Box::new(|c: &mut Check| c.actions = Some(vec!["clippy".into()])),
            ),
            (
                "toolchain",
                Box::new(|c: &mut Check| c.toolchain = Some("nightly".into())),
            ),
            (
                "inputs",
                Box::new(|c: &mut Check| c.cache_inputs = Some(vec!["src/**".into()])),
            ),
        ] {
            let mut changed = check.clone();
            change(&mut changed);
            distinct(label, key(root.path(), &changed, &env));
        }
        // Semantic environment: flags, target, linker, locale, declared extras.
        for (name, value) in [
            ("RUSTFLAGS", "-Dwarnings"),
            ("CARGO_BUILD_TARGET", "aarch64-unknown-linux-gnu"),
            ("CI_LINKER", "mold"),
            ("CARGO_PROFILE_RELEASE_LTO", "fat"),
            ("TZ", "UTC"),
            ("CC", "clang"),
            ("FONTCONFIG_FILE", "/ambient/fonts.conf"),
        ] {
            let mut changed = env.clone();
            changed.insert(name.into(), value.into());
            distinct(name, key(root.path(), &check, &changed));
        }
        let declared = Check {
            cache_env: vec!["MY_FLAG".into()],
            ..check.clone()
        };
        let mut flagged = env.clone();
        flagged.insert("MY_FLAG".into(), "1".into());
        let without = key(root.path(), &declared, &env);
        distinct(
            "declared env present",
            key(root.path(), &declared, &flagged),
        );
        assert_ne!(
            without, baseline,
            "declaring an env input is part of the check identity"
        );
        // Toolchain: the tool a command names, another program on PATH, the
        // runner's cargo configuration.
        let upgraded = tools_dir("v2");
        distinct(
            "tool bytes",
            key(root.path(), &check, &environment(upgraded.path())),
        );
        let extra = tools_dir("v1");
        fs::write(extra.path().join("other"), "x").unwrap();
        distinct(
            "another tool on PATH",
            key(root.path(), &check, &environment(extra.path())),
        );
        let home = tempfile::tempdir().unwrap();
        let mut with_home = env.clone();
        with_home.insert("CARGO_HOME".into(), home.path().as_os_str().to_owned());
        distinct(
            "cargo home absent config",
            key(root.path(), &check, &with_home),
        );
        fs::write(home.path().join("config.toml"), "[build]\nrustflags = []\n").unwrap();
        distinct("cargo home config", key(root.path(), &check, &with_home));
        fs::write(
            home.path().join("config.toml"),
            "[build]\nrustflags = [\"-C\", \"x\"]\n",
        )
        .unwrap();
        distinct(
            "cargo home config edit",
            key(root.path(), &check, &with_home),
        );
    }

    #[test]
    fn location_provenance_url_and_run_metadata_never_change_the_key() {
        let files = [("src/main.txt", "one"), (".ci/ccid.toml", "schema = 1")];
        let check = base_check();
        let (first_tools, second_tools) = (tools_dir("v1"), tools_dir("v1"));
        let (first, second) = (source(&files), source(&files));
        assert_ne!(first.path(), second.path());
        assert_ne!(first_tools.path(), second_tools.path());
        let mut env = environment(first_tools.path());
        let baseline = key(first.path(), &check, &env);
        // A different checkout path and an equivalent tool directory elsewhere.
        assert_eq!(
            key(second.path(), &check, &environment(second_tools.path())),
            baseline
        );
        for (name, value) in [
            ("CI_COMMIT_SHA", "b".repeat(40)),
            ("CI_COMMIT_BRANCH", "feature".into()),
            (
                "CI_REPOSITORY_URL",
                "https://forge.example.invalid/a/b".into(),
            ),
            ("CI_PIPELINE_NUMBER", "77".into()),
            ("CI_JOB_ID", "9".into()),
            ("TMPDIR", "/tmp/another".into()),
            ("HOME", "/home/another".into()),
            ("CARGO_TARGET_DIR", "/tmp/targets".into()),
            ("CCID_REMOTE_CACHE", "grpc://cache.invalid:9092".into()),
        ] {
            env.insert(name.into(), value.into());
            assert_eq!(
                key(first.path(), &check, &env),
                baseline,
                "{name} leaked into the key"
            );
        }
        // A pure declaration is identical whether spelled out or defaulted.
        let spelled = Check {
            cache_pure: Some(true),
            ..check.clone()
        };
        assert_eq!(key(first.path(), &spelled, &env), baseline);
    }

    #[test]
    fn declarations_that_need_no_cache_are_not_part_of_the_key() {
        let encoded = serde_json::to_value(base_check()).unwrap();
        assert!(encoded.get("cache_pure").is_none());
    }
}
