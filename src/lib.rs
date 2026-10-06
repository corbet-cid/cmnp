//! cmnp: moon and proto execution behind ccid's stable `cached` command.
//!
//! ccid owns the manifest and check definitions; this crate owns how moon and
//! proto run them. Each selected check becomes one moon task whose command is
//! the ordinary tool check for that check. moon hashes the task's inputs,
//! skips work whose inputs already passed, and can share results through a
//! remote cache. See `templates/` for reference moon and proto configuration.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, ffi::OsString, fs, io, path::Path, sync::atomic::AtomicBool};

pub static INTERRUPTED: AtomicBool = AtomicBool::new(false);
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type Environment = BTreeMap<OsString, OsString>;

pub mod executor;
mod process;

fn failure(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::other(message.into()).into()
}

fn validate_command(argv: &[String]) -> Result<()> {
    if argv.first().is_none_or(String::is_empty) || argv.iter().any(|arg| arg.contains('\0')) {
        return Err(failure(
            "Commands require a nonempty executable and arguments without NUL bytes",
        ));
    }
    Ok(())
}

fn value(environment: &Environment, name: &str) -> Option<String> {
    environment
        .get(&OsString::from(name))
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned())
}

fn event(value: serde_json::Value) {
    println!("{value}");
    append_receipt(&value);
}

/// Optional machine-readable copy of every event, enabled by `CCID_RECEIPT=<file>`.
/// The receipt file is a cached task output, so a result restored from the
/// cache still carries the receipt of the run that produced it.
fn append_receipt(value: &serde_json::Value) {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    static RECEIPT: OnceLock<Option<Mutex<fs::File>>> = OnceLock::new();
    let file = RECEIPT.get_or_init(|| {
        let path = std::env::var_os("CCID_RECEIPT").filter(|p| !p.is_empty())?;
        let path = Path::new(&path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = fs::create_dir_all(parent);
        }
        match fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Some(Mutex::new(file)),
            Err(error) => {
                eprintln!("cmnp: cannot open CCID_RECEIPT {}: {error}", path.display());
                None
            }
        }
    });
    if let Some(file) = file {
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{value}");
        }
    }
}
