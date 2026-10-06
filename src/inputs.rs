//! Content snapshots using Git's native pathspec matcher, including archive worktrees.
use crate::{executor::Check, failure, process::Runner, value, Environment, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub fn file_digest(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn executable(name: &str, env: &Environment) -> Result<PathBuf> {
    if Path::new(name).is_absolute() {
        return Ok(Path::new(name).canonicalize()?);
    }
    let paths = env
        .get(std::ffi::OsStr::new("PATH"))
        .ok_or_else(|| failure("Missing tool PATH"))?;
    std::env::split_paths(paths)
        .map(|p| p.join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| failure(format!("Missing cache tool: {name}")))?
        .canonicalize()
        .map_err(Into::into)
}

/// Native Nix closure hashes bind immutable runtime dependencies as well as
/// executable bytes. Non-store tools require explicit additional tool probes
/// for their runtime; deployment supplies the loader through NIX_LD.
pub fn tool_digest(
    name: &str,
    runner: &Runner,
    memo: &mut BTreeMap<Vec<String>, String>,
) -> Result<String> {
    let token = vec!["content-digest".into(), name.into()];
    if let Some(digest) = memo.get(&token) {
        return Ok(digest.clone());
    }
    let digest = tool_set_digest(&BTreeMap::from([("tool".into(), name.into())]), runner)?;
    memo.insert(token, digest.clone());
    Ok(digest)
}

/// Query shared immutable runtime closures once for the complete tool set.
/// Mutable executable bytes remain hashed on every invocation; no mtime memo.
pub fn tool_set_digest(names: &BTreeMap<String, String>, runner: &Runner) -> Result<String> {
    let mut binaries = BTreeMap::new();
    let mut paths = Vec::new();
    for (role, name) in names {
        let path = executable(name, &runner.environment)?;
        binaries.insert(role, file_digest(&path)?);
        paths.push(path);
    }
    let mut roots = BTreeSet::new();
    for path in paths
        .into_iter()
        .chain(value(&runner.environment, "NIX_LD").map(PathBuf::from))
        .chain(
            value(&runner.environment, "NIX_LD_LIBRARY_PATH")
                .into_iter()
                .flat_map(|v| std::env::split_paths(&v).collect::<Vec<_>>()),
        )
    {
        let resolved = path.canonicalize()?;
        if let Ok(relative) = resolved.strip_prefix("/nix/store") {
            if let Some(part) = relative.components().next() {
                roots.insert(
                    Path::new("/nix/store")
                        .join(part.as_os_str())
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut parts = vec![serde_json::to_string(&binaries)?];
    if !roots.is_empty() {
        let mut query = vec!["nix-store".into(), "--query".into(), "--requisites".into()];
        query.extend(roots);
        let closure = runner.run(&query, true)?;
        let paths: BTreeSet<&str> = closure.lines().collect();
        let mut hashes = vec!["nix-store".into(), "--query".into(), "--hash".into()];
        hashes.extend(paths.into_iter().map(str::to_owned));
        let mut values: Vec<String> = runner
            .run(&hashes, true)?
            .lines()
            .map(str::to_owned)
            .collect();
        values.sort();
        parts.extend(values);
    }
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&parts)?)))
}

#[derive(Serialize)]
struct Leaf {
    path: String,
    kind: &'static str,
    executable: bool,
    digest: Option<String>,
    target: Option<String>,
}

fn leaves(root: &Path, path: &Path, result: &mut BTreeMap<String, Leaf>) -> Result<()> {
    let relative = path
        .strip_prefix(root)?
        .to_str()
        .ok_or_else(|| failure("Input paths require UTF-8"))?
        .replace('\\', "/");
    let meta = fs::symlink_metadata(path)?;
    if meta.is_dir() {
        result.insert(
            relative.clone(),
            Leaf {
                path: relative,
                kind: "directory",
                executable: false,
                digest: None,
                target: None,
            },
        );
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_name() != ".git" {
                leaves(root, &entry.path(), result)?;
            }
        }
    } else if meta.is_symlink() {
        let target = fs::read_link(path)?;
        let resolved = path.canonicalize()?;
        if !resolved.starts_with(root) || !resolved.is_file() {
            return Err(failure(
                "Cached symlinks must resolve to files inside the source closure",
            ));
        }
        result.insert(
            relative.clone(),
            Leaf {
                path: relative,
                kind: "symlink",
                executable: false,
                digest: Some(file_digest(&resolved)?),
                target: Some(
                    target
                        .to_str()
                        .ok_or_else(|| failure("Symlink target requires UTF-8"))?
                        .into(),
                ),
            },
        );
    } else if meta.is_file() {
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        result.insert(
            relative.clone(),
            Leaf {
                path: relative,
                kind: "file",
                executable,
                digest: Some(file_digest(path)?),
                target: None,
            },
        );
    } else {
        return Err(failure("Special files cannot be cached inputs"));
    }
    Ok(())
}

/// Git supplies glob semantics; no hand-written glob implementation. An archive
/// receives a temporary metadata directory, never an invented source commit.
pub fn source_digest(root: &Path, check: &Check, env: &Environment) -> Result<String> {
    let metadata = tempfile::tempdir()?;
    let mut git = vec!["git".into(), "-c".into(), "core.hooksPath=/dev/null".into()];
    let runner = Runner::new(root.into(), env.clone(), Duration::from_secs(120))?;
    if !root.join(".git").exists() {
        git.extend([
            "--git-dir".into(),
            metadata.path().to_string_lossy().into_owned(),
            "--work-tree".into(),
            root.to_string_lossy().into_owned(),
        ]);
        let mut init = git.clone();
        init.extend(["init".into(), "--quiet".into()]);
        runner.run(&init, true)?;
    }
    for output in &check.cache_outputs {
        let mut tracked = git.clone();
        tracked.extend([
            "ls-files".into(),
            "--cached".into(),
            "-z".into(),
            "--".into(),
            output.clone(),
        ]);
        if !runner.run_raw(&tracked)?.is_empty() {
            return Err(failure(
                "Cached outputs must not overwrite tracked source inputs",
            ));
        }
    }
    let mut command = git;
    command.extend([
        "ls-files".into(),
        "--cached".into(),
        "--others".into(),
        "-z".into(),
        "--".into(),
    ]);
    for pattern in check
        .cache_inputs
        .clone()
        .unwrap_or_else(|| vec!["**/*".into()])
    {
        command.push(match pattern.strip_prefix('!') {
            Some(p) => format!(":(glob,exclude){p}"),
            None => format!(":(glob){pattern}"),
        });
    }
    // Locks and tool configuration cannot be accidentally excluded by a narrow declaration.
    let required: &[&str] = match check.kind.as_str() {
        "cargo" => &[
            "**/Cargo.toml",
            "**/Cargo.lock",
            "**/.cargo/**",
            "**/rust-toolchain*",
        ],
        "javascript" => &[
            "**/package.json",
            "**/package-lock.json",
            "**/pnpm-lock.yaml",
            "**/bun.lock*",
            "**/.npmrc",
            "**/pnpm-workspace.yaml",
        ],
        "nix" => &["**/*"],
        _ => &[],
    };
    for path in [
        ".git/**",
        ".moon/**",
        ".ccid/**",
        "moon.yml",
        "target/**",
        "node_modules/**",
    ] {
        command.push(format!(":(glob,exclude){path}"));
    }
    // Declared outputs are not source inputs. Tracked output/input overlap is
    // rejected below instead of silently hiding source dependencies.
    for output in &check.cache_outputs {
        command.push(format!(":(glob,exclude){output}"));
        command.push(format!(":(glob,exclude){output}/**"));
    }
    let selected = runner.run_raw(&command)?;
    let mut files: BTreeSet<String> = selected
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if !required.is_empty() {
        let separator = command
            .iter()
            .position(|s| s == "--")
            .ok_or_else(|| failure("Missing pathspec boundary"))?;
        command.truncate(separator + 1);
        command.extend(required.iter().map(|s| format!(":(glob){s}")));
        // Required paths are gathered separately so a negative user glob cannot hide them.
        let forced = runner.run_raw(&command)?;
        files.extend(
            forced
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
    }
    let mut snapshot = BTreeMap::new();
    for path in files {
        if path
            .split('/')
            .any(|p| matches!(p, ".git" | ".moon" | ".ccid" | "target" | "node_modules"))
            || path == "moon.yml"
        {
            continue;
        }
        leaves(root, &root.join(path), &mut snapshot)?;
    }
    if snapshot.is_empty() {
        return Err(failure("Empty input closure is not cacheable"));
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&snapshot.values().collect::<Vec<_>>())?)
    ))
}

pub fn lock_digest(root: &Path, check: &Check) -> Result<String> {
    let candidates: &[&str] = match check.kind.as_str() {
        "cargo" => &["Cargo.lock"],
        "nix" => &["flake.lock"],
        "javascript" => match check.manager.as_deref().unwrap_or("npm") {
            "npm" => &["package-lock.json"],
            "pnpm" => &["pnpm-lock.yaml"],
            "bun" => &["bun.lock", "bun.lockb"],
            _ => return Err(failure("Unsupported package manager")),
        },
        _ => return Ok(format!("{:x}", Sha256::digest(b"no-dependency-lock"))),
    };
    for candidate in candidates {
        if root.join(candidate).is_file() {
            return file_digest(&root.join(candidate));
        }
    }
    Err(failure("Result caching requires a dependency lockfile"))
}

pub const SEMANTIC_ENV: &[&str] = &[
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "RUSTC_BOOTSTRAP",
    "RUSTUP_TOOLCHAIN",
    "CARGO_BUILD_TARGET",
    "CARGO_INCREMENTAL",
    "CI_LINKER",
    "CI_TEST_THREADS",
    "RUST_TEST_THREADS",
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "NIX_CONFIG",
    "NODE_OPTIONS",
    "NODE_ENV",
    "TZ",
    "LANG",
    "LC_ALL",
];

pub fn semantic_environment(check: &Check, env: &Environment) -> BTreeMap<String, Option<String>> {
    SEMANTIC_ENV
        .iter()
        .map(|s| (*s).to_owned())
        .chain(check.cache_env.iter().cloned())
        .chain(
            env.keys()
                .filter_map(|s| s.to_str())
                .filter(|s| s.starts_with("CARGO_PROFILE_"))
                .map(str::to_owned),
        )
        .map(|key| {
            let v = env
                .get(std::ffi::OsStr::new(&key))
                .map(|v| v.to_string_lossy().into_owned());
            (key, v)
        })
        .collect()
}

/// Runtime plumbing is explicit. Credentials and arbitrary inherited variables
/// are not handed to cacheable work. Check-specific semantic env is hashed.
pub fn execution_environment(check: &Check, env: &Environment) -> Environment {
    let mut result = Environment::new();
    let plumbing = [
        "PATH",
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "CARGO_TARGET_DIR",
        "CI_CACHE_ROOT",
        "CI_REPOSITORY_URL",
        "CI_JOBS",
        "CI_MEMORY_MB",
        "CI_MEMORY_PER_JOB_MB",
        "CI_MIN_AVAILABLE_MB",
        "CI_TIMEOUT",
        "CI_NIX_JOBS",
        "CI_NIX_CORES",
        "TMPDIR",
        "RUNNER_TEMP",
        "RUSTC_WRAPPER",
        "SCCACHE_DIR",
        "SCCACHE_CACHE_SIZE",
        "SSL_CERT_FILE",
        "NIX_SSL_CERT_FILE",
        "NIX_LD",
        "NIX_LD_LIBRARY_PATH",
        "PROTO_HOME",
        "MOON_HOME",
        "CCID_REMOTE_CACHE",
        "CMNP_TIME",
    ];
    for key in plumbing
        .iter()
        .copied()
        .chain(SEMANTIC_ENV.iter().copied())
        .chain(check.cache_env.iter().map(String::as_str))
    {
        if let Some(v) = env.get(std::ffi::OsStr::new(key)) {
            result.insert(key.into(), v.clone());
        }
    }
    for (k, v) in env {
        if k.to_string_lossy().starts_with("CARGO_PROFILE_") {
            result.insert(k.clone(), v.clone());
        }
    }
    result.insert("CCID_CACHE_CHILD".into(), "1".into());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_environment_preserves_present_empty_flags() {
        let check = Check::default();
        let absent = Environment::new();
        let mut empty = Environment::new();
        empty.insert("CARGO_ENCODED_RUSTFLAGS".into(), "".into());
        assert_ne!(
            semantic_environment(&check, &absent),
            semantic_environment(&check, &empty)
        );
    }

    fn tree(root: &Path) {
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='fixture'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
        fs::write(root.join("README.md"), "Documentation\n").unwrap();
    }

    #[test]
    fn archive_keys_ignore_location_and_force_lock_inputs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        tree(a.path());
        tree(b.path());
        let env = std::env::vars_os().collect();
        let check = Check {
            kind: "cargo".into(),
            cache_inputs: Some(vec!["src/**".into(), "!Cargo.lock".into()]),
            ..Check::default()
        };
        let before = source_digest(a.path(), &check, &env).unwrap();
        assert_eq!(before, source_digest(b.path(), &check, &env).unwrap());
        fs::write(b.path().join("README.md"), "Unrelated documentation\n").unwrap();
        assert_eq!(before, source_digest(b.path(), &check, &env).unwrap());
        fs::write(b.path().join("Cargo.lock"), "version = 4\n# changed\n").unwrap();
        assert_ne!(before, source_digest(b.path(), &check, &env).unwrap());
    }

    #[test]
    fn conservative_defaults_include_readmes_and_reject_external_links() {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let check = Check {
            kind: "cargo".into(),
            ..Check::default()
        };
        let env = std::env::vars_os().collect();
        let before = source_digest(root.path(), &check, &env).unwrap();
        fs::write(
            root.path().join("README.md"),
            "Changed potential include_str input\n",
        )
        .unwrap();
        assert_ne!(before, source_digest(root.path(), &check, &env).unwrap());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", root.path().join("src/outside")).unwrap();
            assert!(source_digest(root.path(), &check, &env).is_err());
        }
    }

    #[test]
    fn semantic_env_is_hashed_and_unknown_ambient_env_is_not_forwarded() {
        let check = Check {
            cache_env: vec!["FEATURE".into()],
            ..Check::default()
        };
        let env = Environment::from([
            ("FEATURE".into(), "yes".into()),
            ("SECRET_TOKEN".into(), "never-forward".into()),
            ("CI_COMMIT_SHA".into(), "a".repeat(40).into()),
            ("PATH".into(), "/bin".into()),
        ]);
        let filtered = execution_environment(&check, &env);
        assert!(value(&filtered, "SECRET_TOKEN").is_none());
        assert!(value(&filtered, "CI_COMMIT_SHA").is_none());
        assert_eq!(value(&filtered, "FEATURE").as_deref(), Some("yes"));
        assert_eq!(
            semantic_environment(&check, &env)["FEATURE"].as_deref(),
            Some("yes")
        );
    }
}
