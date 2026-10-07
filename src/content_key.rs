//! Preparatory content-key and single-flight guard API.
//!
//! This module is preparatory only and is NOT wired into `executor` yet. It
//! provides the typed content-key construction from `DESIGN.md` and a
//! shared-file single-flight guard over the RESULT key. Output validation
//! stays the caller's obligation; guards never publish success implicitly.
//!
//! Caller contract (not enforceable by types alone): the key structs carry no
//! provenance field, but that alone cannot stop a caller from embedding a
//! commit id, run id, timestamp, path, or URL inside `commands`, env values,
//! or the config JSON. Callers MUST build those fields from content only, and
//! unknown-field rejection at deserialize time is a backstop, not a
//! substitute, for that discipline.
//!
//! Trust boundary: the coordinator root must be provisioned by the trusted
//! executor (an owned mount, writable only by the executor identity). File
//! locks coordinate mutually trusting scheduler agents; they are not isolation
//! against an adversarial workload. The untrusted repository must never select
//! the root.
//!
//! Lifecycle protocol: `acquire` takes the shared lock and inspects the ledger
//! without writing anything, so a pure cache lookup leaves no tombstone. After
//! a protected lookup confirms a MISS, the owner calls `begin_compute` to mark
//! Running, computes, then consumes the guard with exactly one of
//! `publish_success` / `publish_failure`. Publishing failure is allowed only
//! after the child process-tree termination is PROVED (deadline kill, group
//! kill, and reaped wait all confirmed); when termination cannot be proved,
//! drop the guard without publishing so the Running record refuses the next
//! start until reconciliation.

use crate::{failure, Result, INTERRUPTED};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions, TryLockError},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

/// Schema version of the canonical encoding. Unknown schemas are rejected.
pub const SCHEMA: u32 = 1;

/// Poll interval while waiting for the result-key lock.
const POLL: Duration = Duration::from_millis(20);

/// Upper bound for an attempt-state file. Anything larger is rejected without
/// parsing.
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// Typed content-key inputs. Every field is content; there is deliberately no
/// provenance field (no commits, run ids, timestamps, temp paths, URLs).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentKeyInputs {
    pub schema: u32,
    pub kind: String,
    /// Hex Merkle digest of the relevant input closure.
    pub input_digest: String,
    /// Hex digest of the dependency lock (cargo/nix/js lockfile content).
    pub lock_digest: String,
    /// Effective commands; each argv's first element is the executable and
    /// argument order within an argv is significant. Empty non-first args are
    /// legitimate (e.g. an explicitly empty flag value).
    pub commands: Vec<Vec<String>>,
    /// Hex content digests of executables and runtime closure by role (actual
    /// bytes, never revision strings). A role map, not a set: exchanging two
    /// roles' digests changes the key.
    pub tool_digests: BTreeMap<String, String>,
    /// Platform and ABI descriptor (e.g. os-arch-env).
    pub platform_abi: String,
    /// Declared semantic env: a present key maps to `Some(value)` (possibly
    /// empty); a declared-but-missing variable maps to `None`. Undeclared
    /// variables are absent from the map and never affect the key.
    pub env: BTreeMap<String, Option<String>>,
    /// Typed semantic config of the selected check. Must be a JSON object;
    /// object keys are sorted recursively at encode time, so key order never
    /// affects the digest.
    pub check_config: Value,
    /// Output contract: declared output paths; order-insignificant.
    pub outputs: Vec<String>,
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_role_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl ContentKeyInputs {
    /// Fail-closed validation of the typed inputs.
    pub fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(failure("Unknown content-key schema"));
        }
        if self.kind.is_empty() || self.kind.contains('\0') {
            return Err(failure("Content key kind must be nonempty NUL-free"));
        }
        if !is_hex_digest(&self.input_digest) {
            return Err(failure("Input digest must be 64 lowercase hex"));
        }
        if !is_hex_digest(&self.lock_digest) {
            return Err(failure("Lock digest must be 64 lowercase hex"));
        }
        if self.commands.is_empty() {
            return Err(failure("Content key requires at least one command"));
        }
        for argv in &self.commands {
            if argv.is_empty() {
                return Err(failure("Each command needs an executable"));
            }
            if argv[0].is_empty() {
                return Err(failure("Command executable must be nonempty"));
            }
            if argv.iter().any(|a| a.contains('\0')) {
                return Err(failure("Command args must be NUL-free"));
            }
        }
        if self.tool_digests.is_empty() {
            return Err(failure("Tool digests must name at least one role"));
        }
        for (role, digest) in &self.tool_digests {
            if !is_role_name(role) {
                return Err(failure("Tool digest roles must be plain names"));
            }
            if !is_hex_digest(digest) {
                return Err(failure("Tool digests must be 64 lowercase hex"));
            }
        }
        if self.platform_abi.is_empty() || self.platform_abi.contains('\0') {
            return Err(failure("Platform/ABI must be nonempty NUL-free"));
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains(['=', '\0']) {
                return Err(failure("Semantic env keys must be plain names"));
            }
            if value.as_deref().is_some_and(|v| v.contains('\0')) {
                return Err(failure("Semantic env values must be NUL-free"));
            }
        }
        if !self.check_config.is_object() {
            return Err(failure("Check semantic config must be a JSON object"));
        }
        for output in &self.outputs {
            if output.is_empty() || output.contains('\0') {
                return Err(failure("Output contract entries must be nonempty"));
            }
            let path = Path::new(output);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(failure("Output contract must be relative plain paths"));
            }
        }
        Ok(())
    }

    /// Canonical bytes: compact serde JSON in field declaration order, with
    /// sorted maps (`BTreeMap`), recursively key-sorted config objects, a
    /// sorted deduped output set, and a role-keyed tool map. Command order and
    /// argument order are preserved because they are semantic. Env uses tagged
    /// options: an absent key (undeclared) differs from null
    /// (declared-but-missing) differs from a string value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized.outputs.sort();
        normalized.outputs.dedup();
        normalized.check_config = canonical_value(&normalized.check_config);
        Ok(serde_json::to_vec(&normalized)?)
    }

    /// Hex content key: SHA-256 over the canonical encoding.
    pub fn key_hex(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_bytes()?)))
    }
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for key in keys {
                sorted.insert(key.clone(), canonical_value(&map[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        scalar => scalar.clone(),
    }
}

/// A validated 64-char lowercase hex content key; also safe as a file name.
pub fn validate_key_hex(key: &str) -> Result<()> {
    if is_hex_digest(key) {
        Ok(())
    } else {
        Err(failure("Content key must be 64 lowercase hex"))
    }
}

/// Resolve and verify the trusted coordinator root: it must be absolute, must
/// canonicalize to an existing real directory, and is returned canonicalized.
/// Anything else fails closed with an explicit error (never silently fall back
/// to uncached).
pub fn validate_root(root: &Path) -> Result<PathBuf> {
    if root.as_os_str().is_empty() {
        return Err(failure("Shared result root must not be empty"));
    }
    if !root.is_absolute() {
        return Err(failure("Shared result root must be absolute"));
    }
    let canonical = root
        .canonicalize()
        .map_err(|_| failure("Shared result root is absent or not a directory"))?;
    if !canonical.is_dir() {
        return Err(failure("Shared result root is absent or not a directory"));
    }
    Ok(canonical)
}

fn key_paths(root: &Path, key: &str) -> Result<(PathBuf, PathBuf)> {
    validate_key_hex(key)?;
    Ok((
        root.join(format!("{key}.lock")),
        root.join(format!("{key}.json")),
    ))
}

fn reject_untrusted_file(path: &Path, what: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(failure(format!("{what} must not be a symlink")))
        }
        Ok(meta) if !meta.file_type().is_file() => {
            Err(failure(format!("{what} must be a regular file")))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Attempt state for one content key. Failures are recorded but never reused;
/// only `Success` is a reusable marker, and even then the caller must still
/// check and restore output blobs itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptState {
    pub schema: u32,
    pub key: String,
    pub attempts: u64,
    pub status: Status,
    /// Opaque producer reference (e.g. run/receipt id); informational only and
    /// never part of any content key.
    pub producer: Option<String>,
}

impl AttemptState {
    pub fn is_success(&self) -> bool {
        matches!(self.status, Status::Success)
    }

    fn validate(&self, key: &str) -> Result<()> {
        if self.schema != SCHEMA {
            return Err(failure("Unknown attempt-state schema"));
        }
        if self.key != key {
            return Err(failure("Attempt state key mismatch"));
        }
        if self.attempts == 0 {
            return Err(failure("Attempt count must be positive"));
        }
        Ok(())
    }
}

fn read_state(path: &Path, key: &str) -> Result<Option<AttemptState>> {
    reject_untrusted_file(path, "Attempt state")?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(failure("Attempt state exceeds size bound"));
    }
    let state: AttemptState =
        serde_json::from_slice(&bytes).map_err(|_| failure("Unparseable attempt state"))?;
    state.validate(key)?;
    Ok(Some(state))
}

/// Durably publish state: private temp file in the same directory, synced to
/// storage, atomically renamed, then the parent directory synced so the rename
/// itself is durable. Rename alone is not durability. The lock inode itself is
/// never unlinked. Errors propagate: no compute may start and no success may be
/// claimed on an unpublished record.
fn write_state(state_path: &Path, state: &AttemptState) -> Result<()> {
    let parent = state_path
        .parent()
        .ok_or_else(|| failure("Attempt state path has no parent"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temp, state)?;
    temp.flush()?;
    temp.as_file()
        .sync_all()
        .map_err(|e| failure(format!("Cannot sync attempt state: {e}")))?;
    temp.persist(state_path)
        .map_err(|e| failure(format!("Cannot publish attempt state: {e}")))?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)?
        .sync_all()
        .map_err(|e| failure(format!("Cannot sync coordinator directory: {e}")))?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Err(failure("Durable publication requires Unix directory sync"))
}

/// Exclusive guard over one result key. Holding the guard means holding the
/// shared lock inode. `acquire` writes nothing: a pure lookup that finds a hit
/// (or finds nothing and goes elsewhere, e.g. a remote hit with no local
/// record) leaves no tombstone. Dropping the guard releases the lock and
/// publishes nothing; outcomes are recorded only through the consuming
/// `publish_success` / `publish_failure` calls, so a repeated publish is a
/// compile-time error.
pub struct Guard {
    key: String,
    _lock: File,
    state_path: PathBuf,
    observed: Option<AttemptState>,
    started: bool,
    running_attempts: Option<u64>,
    start_deadline: Instant,
}

impl Guard {
    /// State observed while acquiring the lock. `Some(success)` means another
    /// run already completed this key: release the guard and reuse the outputs
    /// (after checking/restoring blobs). `Some(failed)` means a previous
    /// attempt failed and was never reusable: call `begin_compute` for a fresh
    /// attempt. `None` means no local record exists.
    pub fn observed(&self) -> Option<&AttemptState> {
        self.observed.as_ref()
    }

    pub fn observed_success(&self) -> Option<&AttemptState> {
        self.observed.as_ref().filter(|s| s.is_success())
    }

    pub fn started(&self) -> bool {
        self.started
    }

    /// Mark the start of compute after the protected lookup confirmed a MISS.
    /// Writes the Running record durably. Refuses when compute already started,
    /// when interrupted, and when the key is already complete: a known Success
    /// forbids `begin_compute` even if blobs are missing, because missing blobs
    /// under a successful ledger must be reported as corruption/unavailable
    /// (subject to an explicit recovery policy), never silently recomputed.
    pub fn begin_compute(&mut self) -> Result<AttemptState> {
        if self.started {
            return Err(failure("Compute already started for this guard"));
        }
        if INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= self.start_deadline {
            return Err(failure(
                "Single-flight start interrupted or deadline exceeded; no compute started",
            ));
        }
        if self.observed_success().is_some() {
            return Err(failure(
                "Key already complete; report missing blobs as corruption/unavailable, never silently recompute",
            ));
        }
        let prior = match &self.observed {
            None => 0,
            Some(state) if matches!(state.status, Status::Failed) => state.attempts,
            Some(_) => return Err(failure("Unexpected attempt state")),
        };
        // Re-verify under the continuously held lock; only lock holders write.
        match self.current_state()? {
            None if prior == 0 => {}
            Some(current)
                if matches!(current.status, Status::Failed) && current.attempts == prior => {}
            _ => {
                return Err(failure(
                    "Attempt record changed under lock; refusing to start compute",
                ))
            }
        }
        let attempts = prior
            .checked_add(1)
            .ok_or_else(|| failure("Attempt counter overflow; refusing to conceal retries"))?;
        let state = AttemptState {
            schema: SCHEMA,
            key: self.key.clone(),
            attempts,
            status: Status::Running,
            producer: None,
        };
        write_state(&self.state_path, &state)?;
        self.started = true;
        self.running_attempts = Some(attempts);
        Ok(state)
    }

    /// Explicitly publish success. Consumes the guard: publishing twice is
    /// rejected at compile time. Only this call marks the key reusable.
    pub fn publish_success(self, producer: Option<String>) -> Result<AttemptState> {
        if !self.started {
            return Err(failure(
                "Compute never started; refusing to publish outcome",
            ));
        }
        let mut state = self
            .current_state()?
            .ok_or_else(|| failure("Missing running record"))?;
        if !matches!(state.status, Status::Running) || Some(state.attempts) != self.running_attempts
        {
            return Err(failure("Only this guard's running record can complete"));
        }
        state.status = Status::Success;
        state.producer = producer;
        write_state(&self.state_path, &state)?;
        Ok(state)
    }

    /// Explicitly publish failure. Consumes the guard. Call only after the
    /// child process-tree termination is PROVED (deadline kill, group kill,
    /// and reaped wait all confirmed by the caller); when termination cannot
    /// be proved, drop the guard without publishing so the Running record
    /// refuses the next start until reconciliation. Failed results are never
    /// reused; the next attempt starts a fresh record with an incremented
    /// counter after its own explicit `begin_compute`.
    pub fn publish_failure(self, producer: Option<String>) -> Result<AttemptState> {
        if !self.started {
            return Err(failure(
                "Compute never started; refusing to publish outcome",
            ));
        }
        let mut state = self
            .current_state()?
            .ok_or_else(|| failure("Missing running record"))?;
        if !matches!(state.status, Status::Running) || Some(state.attempts) != self.running_attempts
        {
            return Err(failure("Only this guard's running record can fail"));
        }
        state.status = Status::Failed;
        state.producer = producer;
        write_state(&self.state_path, &state)?;
        Ok(state)
    }

    fn current_state(&self) -> Result<Option<AttemptState>> {
        read_state(&self.state_path, &self.key)
    }
}

/// Acquire the shared lock for `key` and inspect the attempt ledger while
/// holding it. Writes nothing: a lookup that finds a remote hit with no local
/// record, or that finds a local hit, leaves no tombstone. Already-expired
/// deadlines (including zero timeouts) and pending interruption are rejected
/// before acquisition, so no compute can start without a wait budget.
/// Unresolved Running records (possible crash: old children may still hold the
/// target) refuse new work until reconciliation; corrupt, oversized, symlinked,
/// nonregular, or key-mismatched records fail closed the same way.
/// The result ledger declines to serve a key (unresolved Running record,
/// corrupt or untrusted state). No compute has started, so callers degrade to
/// ordinary uncached execution instead of failing the job.
#[derive(Debug)]
pub struct LedgerRefusal(String);

impl std::fmt::Display for LedgerRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LedgerRefusal {}

pub(crate) fn refusal(error: impl std::fmt::Display) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(LedgerRefusal(error.to_string()))
}

pub fn acquire(root: &Path, key: &str, timeout: Duration) -> Result<Guard> {
    if INTERRUPTED.load(Ordering::SeqCst) {
        return Err(failure("Single-flight acquisition interrupted"));
    }
    if timeout.is_zero() {
        return Err(failure("Single-flight requires a nonzero wait budget"));
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| failure("Single-flight deadline is out of range"))?;
    validate_key_hex(key)?;
    let root = validate_root(root)?;
    let (lock_path, state_path) = key_paths(&root, key)?;
    reject_untrusted_file(&lock_path, "Result lock").map_err(refusal)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(refusal)?;
    if !lock.metadata().map_err(refusal)?.is_file() {
        return Err(refusal("Result lock must be a regular file"));
    }
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(failure(
                "Single-flight acquisition interrupted or deadline exceeded",
            ));
        }
        match lock.try_lock() {
            Ok(()) => break,
            Err(TryLockError::WouldBlock) => {
                if INTERRUPTED.load(Ordering::SeqCst) {
                    return Err(failure("Single-flight wait interrupted"));
                }
                if Instant::now() >= deadline {
                    return Err(failure(
                        "Single-flight lock wait timed out; no compute started",
                    ));
                }
                thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
    }
    let observed = read_state(&state_path, key).map_err(refusal)?;
    if INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return Err(failure(
            "Single-flight acquisition interrupted or deadline exceeded",
        ));
    }
    if let Some(state) = &observed {
        if matches!(state.status, Status::Running) {
            return Err(refusal(
                "Unresolved running record; refuse new compute until reconciliation proves old children are gone",
            ));
        }
    }
    Ok(Guard {
        key: key.to_owned(),
        _lock: lock,
        state_path,
        observed,
        started: false,
        running_attempts: None,
        start_deadline: deadline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_start_deadline_cannot_publish_a_running_record() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let mut owner = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        owner.start_deadline = Instant::now();
        assert!(owner.begin_compute().is_err());
        assert!(!dir.path().join(format!("{key}.json")).exists());
    }

    #[test]
    fn unresolved_running_record_is_a_typed_ledger_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        {
            let mut owner = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
            owner.begin_compute().unwrap();
            // Dropped without publishing, as after a hard kill of the owner.
        }
        let error = acquire(dir.path(), &key, Duration::from_secs(5))
            .err()
            .unwrap();
        assert!(error.downcast_ref::<LedgerRefusal>().is_some());
    }

    #[test]
    fn published_failure_permits_a_fresh_attempt_of_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let mut first = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        first.begin_compute().unwrap();
        first.publish_failure(None).unwrap();
        let mut second = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        assert_eq!(second.begin_compute().unwrap().attempts, 2);
    }

    fn digest(byte: u8) -> String {
        format!("{:x}", Sha256::digest([byte; 8]))
    }

    fn tools(pair: [(&str, u8); 2]) -> BTreeMap<String, String> {
        BTreeMap::from([
            (pair[0].0.to_owned(), digest(pair[0].1)),
            (pair[1].0.to_owned(), digest(pair[1].1)),
        ])
    }

    fn fixture() -> ContentKeyInputs {
        ContentKeyInputs {
            schema: SCHEMA,
            kind: "cargo".into(),
            input_digest: digest(1),
            lock_digest: digest(2),
            commands: vec![
                vec!["cargo".into(), "test".into(), "--locked".into()],
                vec![
                    "cargo".into(),
                    "clippy".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
            ],
            tool_digests: tools([("compiler", 3), ("linker", 4)]),
            platform_abi: "linux-x86_64-gnu".into(),
            env: BTreeMap::from([("CI_JOBS".into(), Some("2".into()))]),
            check_config: serde_json::json!({"actions": ["test"], "release": false}),
            outputs: vec!["target/report".into()],
        }
    }

    #[test]
    fn unknown_provenance_fields_rejected_at_deserialize() {
        // The typed structs are the whole key vocabulary: a commit/run field
        // smuggled into stored JSON must fail, not be ignored.
        let mut raw = serde_json::to_value(fixture()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("commit".into(), Value::String("a".repeat(40)));
        assert!(serde_json::from_value::<ContentKeyInputs>(raw).is_err());
        let state = AttemptState {
            schema: SCHEMA,
            key: digest(1),
            attempts: 1,
            status: Status::Running,
            producer: None,
        };
        let mut raw = serde_json::to_value(&state).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("run_id".into(), Value::String("7".into()));
        assert!(serde_json::from_value::<AttemptState>(raw).is_err());
        // The type also cannot prevent a caller from embedding provenance
        // inside argv/env/config strings; that remains a caller-contract
        // obligation on whoever constructs these fields.
    }

    #[test]
    fn same_content_built_in_different_order_shares_key() {
        let first = fixture();
        let mut second = fixture();
        second.env = BTreeMap::from([
            ("LATER".into(), Some("x".into())),
            ("CI_JOBS".into(), Some("2".into())),
        ]);
        let mut first_extra = first.clone();
        first_extra.env.insert("LATER".into(), Some("x".into()));
        assert_eq!(first_extra.key_hex().unwrap(), second.key_hex().unwrap());
        assert_eq!(
            first_extra.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn tool_role_swap_changes_key() {
        let base = fixture().key_hex().unwrap();
        let mut swapped = fixture();
        swapped.tool_digests = tools([("compiler", 4), ("linker", 3)]);
        assert_ne!(swapped.key_hex().unwrap(), base);
        let mut renamed = fixture();
        renamed.tool_digests = tools([("compiler", 3), ("runner", 4)]);
        assert_ne!(renamed.key_hex().unwrap(), base);
    }

    #[test]
    fn config_object_key_order_irrelevant_but_content_matters() {
        let base = fixture().key_hex().unwrap();
        let mut reordered = fixture();
        reordered.check_config = serde_json::json!({"release": false, "actions": ["test"]});
        assert_eq!(reordered.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.check_config = serde_json::json!({"actions": ["clippy"], "release": false});
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut scalar = fixture();
        scalar.check_config = Value::String("test".into());
        assert!(scalar.key_hex().is_err());
    }

    #[test]
    fn every_content_field_changes_the_key() {
        let base = fixture().key_hex().unwrap();
        let mut changed = fixture();
        changed.input_digest = digest(9);
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.lock_digest = digest(9);
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.commands[0].push("--release".into());
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.commands.push(vec!["true".into()]);
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.tool_digests.insert("compiler".into(), digest(9));
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.platform_abi = "linux-aarch64-gnu".into();
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.env.insert("CI_JOBS".into(), Some("4".into()));
        assert_ne!(changed.key_hex().unwrap(), base);
        // Missing vs empty is a distinct input.
        let mut changed = fixture();
        changed.env.insert("FEATURE_X".into(), None);
        let missing = changed.key_hex().unwrap();
        changed.env.insert("FEATURE_X".into(), Some(String::new()));
        assert_ne!(changed.key_hex().unwrap(), missing);
        let mut changed = fixture();
        changed.outputs = vec!["target/other".into()];
        assert_ne!(changed.key_hex().unwrap(), base);
        let mut changed = fixture();
        changed.kind = "nix".into();
        assert_ne!(changed.key_hex().unwrap(), base);
    }

    #[test]
    fn commands_validate_executable_and_nul_but_allow_empty_flags() {
        let mut ok = fixture();
        ok.commands = vec![vec!["true".into(), String::new()]];
        assert!(ok.key_hex().is_ok());
        for bad in [
            Vec::<Vec<String>>::new(),
            vec![Vec::<String>::new()],
            vec![vec![String::new()]],
            vec![vec!["true".into(), "a\0b".into()]],
        ] {
            let mut check = fixture();
            check.commands = bad;
            assert!(check.key_hex().is_err());
        }
    }

    #[test]
    fn invalid_keys_and_roots_are_rejected() {
        assert!(validate_key_hex(&digest(1)).is_ok());
        for bad in ["", "xyz", &"a".repeat(63), &"A".repeat(64), "../escape"] {
            assert!(validate_key_hex(bad).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_root(dir.path()).is_ok());
        assert!(validate_root(&dir.path().join("absent")).is_err());
        assert!(validate_root(Path::new("relative/root")).is_err());
        let file = dir.path().join("file");
        std::fs::write(&file, "x").unwrap();
        assert!(validate_root(&file).is_err());
        assert!(acquire(
            &dir.path().join("absent"),
            &digest(1),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(acquire(dir.path(), "not-hex", Duration::from_secs(1)).is_err());
        assert!(acquire(dir.path(), &digest(1), Duration::ZERO).is_err());
        let mut bad = fixture();
        bad.schema = 999;
        assert!(bad.key_hex().is_err());
    }

    #[test]
    fn waiter_blocks_until_owner_finishes_and_sees_one_attempt() {
        use std::sync::mpsc;
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let mut owner = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        assert!(owner.observed_success().is_none());
        assert!(!owner.started());
        let (attempting_tx, attempting_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<u64>();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                attempting_tx.send(()).unwrap();
                let waiter = acquire(dir.path(), &key, Duration::from_secs(10)).unwrap();
                let hit = waiter.observed_success().unwrap();
                done_tx.send(hit.attempts).unwrap();
            });
            // The waiter announced itself and is now blocked on the lock the
            // owner holds; completion before the owner releases is impossible,
            // so this assertion rests on the lock, not on timing.
            attempting_rx.recv().unwrap();
            assert!(done_rx.try_recv().is_err());
            owner.begin_compute().unwrap();
            let state = owner.publish_success(Some("producer-a".into())).unwrap();
            assert_eq!(state.attempts, 1);
            // publish_success consumed the guard, releasing the lock, so the
            // waiter below can now proceed.
            assert_eq!(done_rx.recv_timeout(Duration::from_secs(10)).unwrap(), 1);
        });
        // Lock inode is never unlinked by waiting.
        assert!(dir.path().join(format!("{key}.lock")).exists());
    }

    #[test]
    fn pristine_acquire_drop_leaves_no_tombstone_but_start_does() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        {
            let _lookup = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
            // Pure lookup: dropped without begin_compute.
        }
        assert!(!dir.path().join(format!("{key}.json")).exists());
        {
            let mut compute = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
            compute.begin_compute().unwrap();
            // Dropped without publish: silent success is impossible, and the
            // abandoned Running record must refuse the next start.
        }
        assert!(dir.path().join(format!("{key}.json")).exists());
        assert!(acquire(dir.path(), &key, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn malformed_mismatch_and_symlink_records_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let state_path = dir.path().join(format!("{key}.json"));
        std::fs::write(&state_path, b"not json").unwrap();
        assert!(acquire(dir.path(), &key, Duration::from_secs(1)).is_err());
        let foreign = AttemptState {
            schema: SCHEMA,
            key: digest(9),
            attempts: 1,
            status: Status::Success,
            producer: None,
        };
        std::fs::write(&state_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(acquire(dir.path(), &key, Duration::from_secs(1)).is_err());
        std::fs::write(&state_path, vec![b'x'; 65 * 1024]).unwrap();
        assert!(acquire(dir.path(), &key, Duration::from_secs(1)).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_file(&state_path).unwrap();
            std::os::unix::fs::symlink("/etc/hostname", &state_path).unwrap();
            assert!(acquire(dir.path(), &key, Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn publish_requires_begin_and_begin_rejects_repeats_and_hits() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let fresh = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        assert!(fresh.publish_success(None).is_err());
        let mut compute = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        compute.begin_compute().unwrap();
        assert!(compute.begin_compute().is_err());
        compute.publish_success(None).unwrap();
        // Both guards are consumed by their publish calls; a second publish is
        // a compile-time error, and begin on a completed key is refused below.
        let mut hit = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        assert!(hit.begin_compute().is_err());
    }

    #[test]
    fn failure_retry_requires_explicit_begin_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let mut first = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        first.begin_compute().unwrap();
        first.publish_failure(None).unwrap();
        let mut second = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        // A recorded failure is not a hit and starts nothing by itself.
        assert!(second.observed_success().is_none());
        assert!(!second.started());
        let running = second.begin_compute().unwrap();
        assert_eq!(running.attempts, 2);
        let done = second.publish_success(None).unwrap();
        assert_eq!(done.attempts, 2);
        assert!(done.is_success());
    }

    #[test]
    fn lock_timeout_changes_no_state_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let key = fixture().key_hex().unwrap();
        let mut owner = acquire(dir.path(), &key, Duration::from_secs(5)).unwrap();
        owner.begin_compute().unwrap();
        let state_path = dir.path().join(format!("{key}.json"));
        let before = std::fs::read(&state_path).unwrap();
        let names_before = sorted_names(dir.path());
        assert!(acquire(dir.path(), &key, Duration::from_millis(80)).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        assert_eq!(sorted_names(dir.path()), names_before);
        drop(owner);
    }

    fn sorted_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}
