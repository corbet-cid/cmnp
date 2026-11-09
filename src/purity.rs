//! Which checks are cached by default.
//!
//! Deterministic checks (format, lint, build, unit tests, docs) are pure: the
//! keyed inputs decide the result, so it may be shared. A few tools instead
//! observe the network or the clock (advisory databases, fetching scenarios);
//! caching them would replay a stale pass. They are recognised conservatively
//! from the declared commands and from the first-level script a command runs,
//! and run uncached unless the manifest says `cache_pure = true`. An explicit
//! `cache_pure = false` always opts a check out.
use crate::executor::Check;
use std::{fs, io::Read, path::Path};

/// Programs that talk to the network or depend on live external state.
const PROGRAMS: &[&str] = &[
    "nc",
    "ncat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ping",
    "dig",
    "nslookup",
    "pip-audit",
    "osv-scanner",
    "trivy",
    "grype",
    "snyk",
    "gh",
    "glab",
    "date",
];
/// Downloaders are volatile unless the same command or script verifies what it
/// fetched: a checksum-verified download is content-pinned.
const DOWNLOADERS: &[&str] = &["curl", "wget"];
/// Tokens that show a fetched artifact is integrity-checked.
const INTEGRITY: &[&str] = &[
    "sha256sum",
    "sha512sum",
    "sha1sum",
    "shasum",
    "b3sum",
    "cosign",
    "minisign",
    "gpgv",
];
/// Program plus subcommand pairs that fetch or consult live databases.
const SUBCOMMANDS: &[(&str, &str)] = &[
    ("cargo", "audit"),
    ("cargo", "deny"),
    ("npm", "audit"),
    ("pnpm", "audit"),
    ("yarn", "audit"),
    ("git", "fetch"),
    ("git", "clone"),
    ("git", "pull"),
    ("git", "push"),
    ("git", "ls-remote"),
    ("nix", "flake"),
];
/// Variable-name prefixes of per-run provenance: a check that reads them is
/// commit- or run-sensitive, which a content key cannot express.
const PROVENANCE_PREFIXES: &[&str] = &[
    "CI_COMMIT_",
    "CI_JOB_",
    "CI_PIPELINE_",
    "CI_RUN_",
    "CI_REPOSITORY_URL",
    "CROW_",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GIT_COMMIT",
];
/// Variable-name fragments of credentials: needing one means needing a service.
const CREDENTIAL_FRAGMENTS: &[&str] = &["_TOKEN", "_SECRET", "PASSWORD", "NETRC", "CREDENTIALS"];
/// Git subcommands that read commit provenance rather than file content.
const PROVENANCE_GIT: &[&str] = &["describe", "log"];
/// Scripts larger than this are not inspected (and then not presumed volatile).
const SCRIPT_LIMIT: u64 = 256 * 1024;

fn separators(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            ';' | '&' | '|' | '(' | ')' | '`' | '$' | '{' | '}' | '"' | '\''
        )
}

/// First volatile program or subcommand in a token stream.
fn find<'a>(tokens: impl Iterator<Item = &'a str>) -> Option<String> {
    let tokens: Vec<&str> = tokens.collect();
    let verified = tokens
        .iter()
        .any(|t| INTEGRITY.contains(&t.rsplit('/').next().unwrap_or(t)));
    for (at, token) in tokens.iter().enumerate() {
        if let Some(prefix) = PROVENANCE_PREFIXES.iter().find(|p| token.starts_with(**p)) {
            let name: String = token
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            return Some(format!(
                "reads run metadata {}",
                if name.len() > prefix.len() {
                    name
                } else {
                    (*prefix).to_owned()
                }
            ));
        }
        let name: String = token
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if name.len() > 6 && CREDENTIAL_FRAGMENTS.iter().any(|f| name.contains(f)) {
            return Some(format!("reads credential {name}"));
        }
        let program = token.rsplit('/').next().unwrap_or(token);
        if program == "git"
            && tokens.get(at + 1).is_some_and(|next| {
                PROVENANCE_GIT.contains(next)
                    || (*next == "rev-parse"
                        && tokens.get(at + 2).is_some_and(|t| t.starts_with("HEAD")))
            })
        {
            return Some(format!("reads commit provenance (git {})", tokens[at + 1]));
        }
        if PROGRAMS.contains(&program) || (DOWNLOADERS.contains(&program) && !verified) {
            return Some(format!("uses {program}"));
        }
        if let Some(next) = tokens.get(at + 1) {
            if let Some((p, s)) = SUBCOMMANDS.iter().find(|(p, s)| *p == program && s == next) {
                // `nix flake` is only volatile when it updates inputs.
                if *p == "nix"
                    && !tokens[at + 2..]
                        .iter()
                        .take(2)
                        .any(|t| *t == "update" || *t == "lock")
                {
                    continue;
                }
                return Some(format!("uses {p} {s}"));
            }
        }
    }
    None
}

fn script_text(root: &Path, argument: &str) -> Option<String> {
    let path = Path::new(argument);
    let known = ["sh", "bash", "py", "mjs", "js", "ts", "rb", "pl"];
    if path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || !path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| known.contains(&e))
    {
        return None;
    }
    let file = root.join(path);
    let meta = fs::symlink_metadata(&file).ok()?;
    if !meta.is_file() || meta.len() > SCRIPT_LIMIT {
        return None;
    }
    let mut text = String::new();
    fs::File::open(file).ok()?.read_to_string(&mut text).ok()?;
    Some(text)
}

/// Why this check must not be cached by default, if it must not.
pub fn volatile_reason(check: &Check, root: &Path) -> Option<String> {
    for command in &check.commands {
        if let Some(found) = find(command.iter().map(String::as_str)) {
            return Some(format!("command {found}"));
        }
        for argument in command.iter().skip(1) {
            let Some(text) = script_text(root, argument) else {
                continue;
            };
            let code = text
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n");
            if let Some(found) = find(code.split(separators).filter(|t| !t.is_empty())) {
                return Some(format!("script {argument} {found}"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(commands: &[&[&str]]) -> Check {
        Check {
            kind: "commands".into(),
            commands: commands
                .iter()
                .map(|c| c.iter().map(|s| (*s).to_owned()).collect())
                .collect(),
            ..Check::default()
        }
    }

    #[test]
    fn live_databases_and_network_tools_are_volatile() {
        let root = tempfile::tempdir().unwrap();
        for command in [
            &["cargo", "deny", "--locked", "check", "advisories"][..],
            &["cargo", "audit"],
            &["npm", "audit", "--omit=dev"],
            &["curl", "-fsS", "https://example.invalid"],
            &["/usr/bin/wget", "x"],
            &["git", "fetch", "origin"],
            &["nix", "flake", "update"],
            &["nix", "flake", "lock", "--update-input", "nixpkgs"],
            &["git", "log", "-1"],
            &["git", "describe", "--tags"],
            &["git", "rev-parse", "HEAD"],
        ] {
            assert!(
                volatile_reason(&check(&[command]), root.path()).is_some(),
                "{command:?}"
            );
        }
    }

    #[test]
    fn deterministic_tools_are_not_volatile() {
        let root = tempfile::tempdir().unwrap();
        for command in [
            &["cargo", "clippy", "--all-targets", "--", "-D", "warnings"][..],
            &["cargo", "fmt", "--check"],
            &["cargo", "test", "--locked"],
            &["npm", "test"],
            &["git", "diff", "--exit-code"],
            &["nix", "flake", "check"],
            &["python3", "-m", "unittest"],
            &["bash", "missing-script.sh"],
            &["git", "rev-parse", "--show-toplevel"],
            &["git", "ls-files"],
        ] {
            assert_eq!(
                volatile_reason(&check(&[command]), root.path()),
                None,
                "{command:?}"
            );
        }
    }

    #[test]
    fn the_first_level_script_is_inspected_ignoring_comments() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".ci")).unwrap();
        let verify = root.path().join(".ci/verify.sh");
        fs::write(
            &verify,
            "#!/bin/bash\n# no curl needed here, git fetch is also fine\ncargo test --locked\n",
        )
        .unwrap();
        let subject = check(&[&["bash", ".ci/verify.sh"]]);
        assert_eq!(volatile_reason(&subject, root.path()), None);
        fs::write(
            &verify,
            "set -e\nout=$(curl -fsS https://example.invalid)\ncargo test\n",
        )
        .unwrap();
        assert_eq!(
            volatile_reason(&subject, root.path()).as_deref(),
            Some("script .ci/verify.sh uses curl")
        );
        fs::write(&verify, "set -e\ncargo deny --locked check advisories\n").unwrap();
        assert_eq!(
            volatile_reason(&subject, root.path()).as_deref(),
            Some("script .ci/verify.sh uses cargo deny")
        );
        fs::write(
            &verify,
            "set -e\n: \"${CI_COMMIT_SHA:?verify requires the exact source revision}\"\ncargo test\n",
        )
        .unwrap();
        assert_eq!(
            volatile_reason(&subject, root.path()).as_deref(),
            Some("script .ci/verify.sh reads run metadata CI_COMMIT_SHA")
        );
        fs::write(&verify, "curl_opts=1\nexport FORGE_TOKEN=x\n").unwrap();
        assert_eq!(
            volatile_reason(&subject, root.path()).as_deref(),
            Some("script .ci/verify.sh reads credential FORGE_TOKEN")
        );
        fs::write(&verify, "echo $CI_JOBS $CI_TIMEOUT $RUNNER_TEMP\n").unwrap();
        assert_eq!(volatile_reason(&subject, root.path()), None);
        // Paths outside the repository are never read.
        let outside = check(&[&["bash", "../verify.sh"], &["bash", "/etc/hostname.sh"]]);
        assert_eq!(volatile_reason(&outside, root.path()), None);
    }
}
