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
            "**/deno.lock",
            "**/deno.json*",
            "**/bunfig.toml",
            "**/.npmrc",
            "**/pnpm-workspace.yaml",
        ],
        "nix" => &["**/*"],
        // A narrow custom-command source declaration must not omit dependency
        // resolution or compiler configuration for any supported ecosystem.
        "commands" => &[
            "**/Cargo.toml",
            "**/Cargo.lock",
            "**/.cargo/**",
            "**/rust-toolchain*",
            "**/go.mod",
            "**/go.sum",
            "**/go.work",
            "**/go.work.sum",
            "**/package.json",
            "**/package-lock.json",
            "**/npm-shrinkwrap.json",
            "**/pnpm-lock.yaml",
            "**/pnpm-workspace.yaml",
            "**/bun.lock*",
            "**/bunfig.toml",
            "**/yarn.lock",
            "**/.yarnrc*",
            "**/.npmrc",
            "**/deno.json*",
            "**/deno.lock",
            "**/tsconfig*.json",
            "**/pyproject.toml",
            "**/uv.lock",
            "**/requirements*.txt",
            "**/poetry.lock",
            "**/Pipfile*",
            "**/.python-version",
            "**/flake.nix",
            "**/flake.lock",
            "**/typst.toml",
            "**/CMakeLists.txt",
            "**/CMakePresets.json",
            "**/conan.lock",
            "**/vcpkg.json",
            "**/vcpkg-configuration.json",
            "**/Dockerfile*",
            "**/.dockerignore",
            "**/docker-bake.*",
            "**/.prototools",
            "**/.tool-versions",
            "**/buf.lock",
            "**/.terraform.lock.hcl",
        ],
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
            "deno" => &["deno.lock"],
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

/// Identity of the directories a command check finds programs in.
///
/// Nix store entries are content addressed, so their store path names them
/// exactly. Entries inside the repository are covered by the source digest.
/// Any other directory is mutable: it contributes a digest of its listing
/// (name, kind, size, link target), so an upgraded tool
/// changes the key. Absent entries cannot supply tools and are skipped. The
/// location of a mutable directory is deliberately not part of the identity.
pub fn path_identity(root: &Path, env: &Environment) -> Result<String> {
    let path = env
        .get(std::ffi::OsStr::new("PATH"))
        .ok_or_else(|| failure("Missing tool PATH"))?;
    let root = root.canonicalize().ok();
    let mut parts = Vec::new();
    for entry in std::env::split_paths(path) {
        let Ok(resolved) = entry.canonicalize() else {
            continue;
        };
        if root.as_ref().is_some_and(|r| resolved.starts_with(r)) {
            continue;
        }
        if let Ok(relative) = resolved.strip_prefix("/nix/store") {
            if let Some(part) = relative.components().next() {
                parts.push(format!("store:{}", part.as_os_str().to_string_lossy()));
                continue;
            }
        }
        parts.push(format!("listing:{}", directory_listing_digest(&resolved)?));
    }
    Ok(format!("{:x}", Sha256::digest(parts.join("\n").as_bytes())))
}

fn directory_listing_digest(directory: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let meta = fs::symlink_metadata(entry.path())?;
        let detail = if meta.is_symlink() {
            format!("link {}", fs::read_link(entry.path())?.display())
        } else {
            format!("file {}", meta.len())
        };
        entries.push(format!("{} {detail}", entry.file_name().to_string_lossy()));
    }
    entries.sort();
    Ok(format!(
        "{:x}",
        Sha256::digest(entries.join("\n").as_bytes())
    ))
}

/// Digest of the cargo configuration the runner supplies through
/// `CARGO_HOME` (`config.toml` or `config`): target linkers, rustflags,
/// source replacement. Absent files are distinct from empty ones.
pub fn cargo_home_config(env: &Environment) -> Result<String> {
    let Some(home) = env.get(std::ffi::OsStr::new("CARGO_HOME")) else {
        return Ok("no-cargo-home".into());
    };
    let mut parts = Vec::new();
    for name in ["config.toml", "config"] {
        let path = Path::new(home).join(name);
        parts.push(if path.is_file() {
            format!("{name}:{}", file_digest(&path)?)
        } else {
            format!("{name}:absent")
        });
    }
    Ok(parts.join(" "))
}

pub const SEMANTIC_ENV: &[&str] = &[
    // Build environment supplied by the runner's toolchain wrapper (values are
    // content-addressed store paths): where headers, libraries and tools are.
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_SYSROOT_DIR",
    "LD_LIBRARY_PATH",
    "LIBRARY_PATH",
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "NIX_CFLAGS_COMPILE",
    "NIX_CFLAGS_LINK",
    "NIX_LDFLAGS",
    "OPENSSL_DIR",
    "OPENSSL_LIB_DIR",
    "OPENSSL_INCLUDE_DIR",
    "PYTHONPATH",
    "NODE_PATH",
    "CHROME_BIN",
    "CHROMEDRIVER",
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
    "GOOS",
    "GOARCH",
    "GOAMD64",
    "GOARM",
    "GOFLAGS",
    "GOEXPERIMENT",
    "GOTOOLCHAIN",
    "CGO_ENABLED",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_LDFLAGS",
    "PYTHONHASHSEED",
    "PYTHONOPTIMIZE",
    "TZ",
    "LANG",
    "LC_ALL",
];

/// Runner plumbing forwarded to cacheable work without entering the key.
const PLUMBING: &[&str] = &[
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
    // Native caches validate their own entries. Their location must reach
    // checked commands without introducing machine paths into content keys.
    "CCACHE_DIR",
    "GOCACHE",
    "GOMODCACHE",
    "npm_config_cache",
    "NPM_CONFIG_CACHE",
    "npm_config_store_dir",
    "pnpm_config_store_dir",
    "PNPM_HOME",
    "YARN_CACHE_FOLDER",
    "UV_CACHE_DIR",
    "UV_PYTHON_INSTALL_DIR",
    "PIP_CACHE_DIR",
    "BUN_INSTALL_CACHE_DIR",
    "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
    "DENO_DIR",
    "NODE_COMPILE_CACHE",
    "TSC_CACHE_DIR",
    "PLAYWRIGHT_BROWSERS_PATH",
    "PUPPETEER_CACHE_DIR",
    "TYPST_PACKAGE_CACHE_PATH",
    "WASM_PACK_CACHE",
    "XDG_CACHE_HOME",
    "NIX_CACHE_HOME",
    "NIX_REMOTE",
    "BUILDKIT_HOST",
    "TF_PLUGIN_CACHE_DIR",
    "SSL_CERT_FILE",
    "NIX_SSL_CERT_FILE",
    "NIX_LD",
    "NIX_LD_LIBRARY_PATH",
    "PROTO_HOME",
    "MOON_HOME",
    "CCID_REMOTE_CACHE",
    "CMNP_TIME",
];

/// Name prefixes and exact names of inherited variables that vary per run, name
/// a job or a location, or reach the network: never forwarded to cacheable work.
const AMBIENT_EXCLUDED_PREFIXES: &[&str] = &[
    "CI_",
    "CCID_",
    "CROW_",
    "CFRG_",
    "SOURCE_",
    "CARGO_TARGET_",
    "DRONE_",
    "PULLREQUEST_",
    "WOODPECKER_",
    "GITHUB_",
    "GITLAB_",
    "KUBERNETES_",
    "BUILDKIT_",
    "GIT_",
    "SSH_",
    "GPG_",
    "DBUS_",
    "MOON_",
    "XDG_RUNTIME_",
    "BASH_FUNC_",
];
const AMBIENT_EXCLUDED_NAMES: &[&str] = &[
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "HOSTNAME",
    "TERM",
    "COLORTERM",
    "LINES",
    "COLUMNS",
    "LS_COLORS",
    "MAIL",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "USERPROFILE",
    "TEMPDIR",
    "NIX_BUILD_TOP",
    "NIX_LOG_FD",
];
const CREDENTIAL_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "NETRC",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE_KEY",
    "API_KEY",
];

/// Inherited variables a custom `commands` check keeps seeing as it would
/// uncached: everything the runner provides except per-run state, credentials
/// and plumbing. They are forwarded AND keyed, so a different toolchain
/// environment can never replay another environment's result. Typed kinds
/// (cargo, javascript, nix) keep their declared environment contract.
/// Per-job directories the runner announces (scratch, working directory): any
/// variable whose value lives under one is about this job, not the check.
fn job_locations(env: &Environment) -> Vec<String> {
    ["TMPDIR", "RUNNER_TEMP", "TEMP", "TMP", "PWD"]
        .iter()
        .filter_map(|name| env.get(std::ffi::OsStr::new(name)))
        .filter_map(|value| value.to_str())
        .filter(|value| Path::new(value).is_absolute() && value.matches('/').count() >= 2)
        .map(str::to_owned)
        .collect()
}
fn names_job_location(value: &str, locations: &[String]) -> bool {
    value.contains("/ccid-job-") || locations.iter().any(|l| value.starts_with(l.as_str()))
}

/// Kubernetes-style service discovery variables (`<SERVICE>_SERVICE_HOST`,
/// `<SERVICE>_PORT_1234_TCP_ADDR`, ...) describe the cluster, not the check.
fn service_discovery(name: &str) -> bool {
    name.ends_with("_SERVICE_HOST")
        || name.contains("_SERVICE_PORT")
        || name.contains("_TCP")
        || name.contains("_UDP")
        || (name.ends_with("_PORT") && name.len() > 5)
}

pub fn ambient_names(check: &Check, env: &Environment) -> Vec<String> {
    if check.kind != "commands" {
        return vec![];
    }
    let locations = job_locations(env);
    env.iter()
        .filter(|(_, value)| !names_job_location(value.to_str().unwrap_or(""), &locations))
        .map(|(key, _)| key)
        .filter_map(|key| key.to_str())
        .filter(|name| {
            !name.is_empty()
                && !PLUMBING.contains(name)
                && !SEMANTIC_ENV.contains(name)
                && !name.starts_with("CARGO_PROFILE_")
                && !AMBIENT_EXCLUDED_NAMES.contains(name)
                && !AMBIENT_EXCLUDED_PREFIXES
                    .iter()
                    .any(|p| name.starts_with(p))
                && !service_discovery(name)
                && !CREDENTIAL_FRAGMENTS
                    .iter()
                    .any(|f| name.to_ascii_uppercase().contains(f))
        })
        .map(str::to_owned)
        .collect()
}

pub fn semantic_environment(check: &Check, env: &Environment) -> BTreeMap<String, Option<String>> {
    SEMANTIC_ENV
        .iter()
        .map(|s| (*s).to_owned())
        .chain(check.cache_env.iter().cloned())
        .chain(ambient_names(check, env))
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
    for key in PLUMBING
        .iter()
        .copied()
        .chain(SEMANTIC_ENV.iter().copied())
        .chain(check.cache_env.iter().map(String::as_str))
    {
        if let Some(v) = env.get(std::ffi::OsStr::new(key)) {
            result.insert(key.into(), v.clone());
        }
    }
    for key in ambient_names(check, env) {
        if let Some(v) = env.get(std::ffi::OsStr::new(&key)) {
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

    #[test]
    fn custom_commands_cannot_hide_dependency_locks_with_narrow_inputs() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("main.txt"), "source").unwrap();
        let check = Check {
            kind: "commands".into(),
            cache_inputs: Some(vec!["main.txt".into()]),
            ..Check::default()
        };
        let env = std::env::vars_os().collect();
        let mut previous = source_digest(root.path(), &check, &env).unwrap();
        for lock in [
            "go.sum",
            "uv.lock",
            "deno.lock",
            "pnpm-lock.yaml",
            "flake.lock",
            "Cargo.lock",
            "conan.lock",
            "buf.lock",
            ".prototools",
        ] {
            fs::write(root.path().join(lock), "locked content").unwrap();
            let current = source_digest(root.path(), &check, &env).unwrap();
            assert_ne!(previous, current, "{lock} must affect the key");
            previous = current;
        }
    }

    #[test]
    fn native_cache_locations_are_forwarded_without_invalidating_results() {
        let check = Check::default();
        for name in [
            "GOCACHE",
            "GOMODCACHE",
            "CCACHE_DIR",
            "npm_config_cache",
            "npm_config_store_dir",
            "UV_CACHE_DIR",
            "PIP_CACHE_DIR",
            "BUN_INSTALL_CACHE_DIR",
            "DENO_DIR",
            "NODE_COMPILE_CACHE",
            "PLAYWRIGHT_BROWSERS_PATH",
            "TYPST_PACKAGE_CACHE_PATH",
            "WASM_PACK_CACHE",
            "NIX_CACHE_HOME",
            "PROTO_HOME",
            "RUSTUP_HOME",
        ] {
            let first = Environment::from([(name.into(), "/cache/one".into())]);
            let second = Environment::from([(name.into(), "/cache/two".into())]);
            assert_eq!(
                value(&execution_environment(&check, &first), name).as_deref(),
                Some("/cache/one")
            );
            assert_eq!(
                semantic_environment(&check, &first),
                semantic_environment(&check, &second)
            );
        }
        let native = Environment::from([("GOFLAGS".into(), "-race".into())]);
        assert_ne!(
            semantic_environment(&check, &native),
            semantic_environment(&check, &Environment::new())
        );
        assert_eq!(
            value(&execution_environment(&check, &native), "GOFLAGS").as_deref(),
            Some("-race")
        );
    }

    fn path_env(entries: &[&Path]) -> Environment {
        let mut env = Environment::new();
        env.insert("PATH".into(), std::env::join_paths(entries).unwrap());
        env
    }

    #[test]
    fn path_identity_follows_tool_content_not_location() {
        let repo = tempfile::tempdir().unwrap();
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let stamp = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for dir in [&a, &b] {
            let file = dir.path().join("tool");
            fs::write(&file, "one").unwrap();
            fs::File::options()
                .write(true)
                .open(&file)
                .unwrap()
                .set_modified(stamp)
                .unwrap();
        }
        let first = path_identity(repo.path(), &path_env(&[a.path()])).unwrap();
        assert_eq!(
            first,
            path_identity(repo.path(), &path_env(&[b.path()])).unwrap()
        );
        // A changed, added or replaced tool changes the identity.
        fs::write(a.path().join("tool"), "longer").unwrap();
        assert_ne!(
            first,
            path_identity(repo.path(), &path_env(&[a.path()])).unwrap()
        );
        fs::write(b.path().join("extra"), "x").unwrap();
        assert_ne!(
            first,
            path_identity(repo.path(), &path_env(&[b.path()])).unwrap()
        );
        // Touching a file without changing it is not an upgrade.
        fs::File::options()
            .write(true)
            .open(b.path().join("tool"))
            .unwrap()
            .set_modified(stamp + Duration::from_secs(99))
            .unwrap();
        assert_eq!(
            path_identity(repo.path(), &path_env(&[b.path()])).unwrap(),
            path_identity(repo.path(), &path_env(&[b.path()])).unwrap()
        );
        // Order matters (it decides which program wins); absent entries do not.
        let missing = repo.path().join("absent-directory");
        assert_eq!(
            path_identity(repo.path(), &path_env(&[a.path(), b.path()])).unwrap(),
            path_identity(repo.path(), &path_env(&[a.path(), &missing, b.path()])).unwrap()
        );
        assert_ne!(
            path_identity(repo.path(), &path_env(&[a.path(), b.path()])).unwrap(),
            path_identity(repo.path(), &path_env(&[b.path(), a.path()])).unwrap()
        );
        // Directories inside the repository are covered by the source digest.
        let inside = repo.path().join("bin");
        fs::create_dir(&inside).unwrap();
        assert_eq!(
            path_identity(repo.path(), &path_env(&[a.path()])).unwrap(),
            path_identity(repo.path(), &path_env(&[a.path(), &inside])).unwrap()
        );
        assert!(path_identity(repo.path(), &Environment::new()).is_err());
    }

    #[test]
    fn cargo_home_configuration_is_part_of_the_toolchain_identity() {
        let home = tempfile::tempdir().unwrap();
        let mut env = Environment::new();
        assert_eq!(cargo_home_config(&env).unwrap(), "no-cargo-home");
        env.insert("CARGO_HOME".into(), home.path().as_os_str().to_owned());
        let absent = cargo_home_config(&env).unwrap();
        fs::write(home.path().join("config.toml"), "").unwrap();
        let empty = cargo_home_config(&env).unwrap();
        fs::write(home.path().join("config.toml"), "[build]\njobs = 1\n").unwrap();
        let set = cargo_home_config(&env).unwrap();
        fs::write(home.path().join("config"), "legacy").unwrap();
        let legacy = cargo_home_config(&env).unwrap();
        let all = [absent, empty, set, legacy];
        for (i, one) in all.iter().enumerate() {
            for other in &all[i + 1..] {
                assert_ne!(one, other);
            }
        }
    }

    #[test]
    fn commands_keep_their_toolchain_environment_keyed_and_forwarded() {
        let commands = Check {
            kind: "commands".into(),
            ..Check::default()
        };
        let mut env = Environment::new();
        for (name, value) in [
            ("FONTCONFIG_FILE", "/store/fonts.conf"),
            ("CHROME_BIN", "/store/chrome"),
            ("SOME_TOOL_HOME", "/store/tool"),
            ("CI_PIPELINE_NUMBER", "7"),
            ("CCID_JOB_REQUEST", "{}"),
            ("CROW_AGENT", "a"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GITHUB_TOKEN", "secret"),
            ("FORGE_PASSWORD", "secret"),
            ("NETRC", "/home/x/.netrc"),
            ("PWD", "/tmp/job"),
            ("TEMPDIR", "/store/elsewhere"),
            ("NIX_BUILD_TOP", "/store/elsewhere"),
            ("UNDER_PWD", "/tmp/job/inner/file"),
            ("SCRATCH_OF_JOB", "/tmp/ccid-job-AbC123/scratch"),
            ("SOURCE_ARCHIVE", "/a.tar"),
            ("DRONE_BUILD_NUMBER", "7"),
            ("PULLREQUEST_DRONE_PULL_REQUEST", "1"),
            ("USERPROFILE", "/tmp/job-home"),
            ("KUBERNETES_SERVICE_HOST", "10.0.0.1"),
            ("BUILDKIT_PORT_1234_TCP_ADDR", "10.0.0.2"),
            ("OTHER_SERVICE_PORT_GRPC", "9092"),
            ("HOME", "/home/runner"),
        ] {
            env.insert(name.into(), value.into());
        }
        let forwarded = execution_environment(&commands, &env);
        for name in ["FONTCONFIG_FILE", "CHROME_BIN", "SOME_TOOL_HOME"] {
            assert!(forwarded.contains_key(std::ffi::OsStr::new(name)), "{name}");
        }
        for name in [
            "CI_PIPELINE_NUMBER",
            "CROW_AGENT",
            "GIT_CONFIG_COUNT",
            "GITHUB_TOKEN",
            "FORGE_PASSWORD",
            "NETRC",
            "PWD",
            "SOURCE_ARCHIVE",
        ] {
            assert!(
                !forwarded.contains_key(std::ffi::OsStr::new(name)),
                "{name} leaked"
            );
        }
        // Plumbing is forwarded but never keyed; ambient variables are keyed.
        let keyed = semantic_environment(&commands, &env);
        assert!(keyed.contains_key("SOME_TOOL_HOME") && keyed.contains_key("FONTCONFIG_FILE"));
        assert!(!keyed.contains_key("HOME") && !keyed.contains_key("CI_PIPELINE_NUMBER"));
        // Typed kinds keep the declared contract only.
        let cargo = Check {
            kind: "cargo".into(),
            ..Check::default()
        };
        assert!(!execution_environment(&cargo, &env)
            .contains_key(std::ffi::OsStr::new("SOME_TOOL_HOME")));
        assert!(!semantic_environment(&cargo, &env).contains_key("SOME_TOOL_HOME"));
    }
}
