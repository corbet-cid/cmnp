//! Bounded child execution for moon probes and moon runs.
//!
//! The environment is always explicit, stdin is always null, and every child
//! runs under a deadline inside its own process group; expiry or interruption
//! terminates the whole group. Captured output is capped at 16 MiB.
use crate::{failure, validate_command, Environment, Result, INTERRUPTED};
use process_wrap::std::{ChildWrapper, CommandWrap};
use serde_json::json;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};

pub struct Runner {
    pub root: PathBuf,
    pub environment: Environment,
    pub(crate) deadline: Instant,
}

struct OwnedChild(Box<dyn ChildWrapper>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

impl Runner {
    pub fn new(root: PathBuf, environment: Environment, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| failure("Deadline is out of range"))?;
        Ok(Self {
            root,
            environment,
            deadline,
        })
    }

    fn command_event(&self, value: serde_json::Value) {
        crate::event(value);
    }

    pub fn run(&self, argv: &[String], capture: bool) -> Result<String> {
        validate_command(argv)?;
        if INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
            return Err(failure("Command interrupted or total deadline exceeded"));
        }
        #[cfg(unix)]
        {
            Ok(String::from_utf8(self.run_unix_bytes(argv, capture)?)?
                .trim()
                .to_owned())
        }
        #[cfg(not(unix))]
        {
            let _ = capture;
            Err(failure("Moon execution requires the verified Unix backend"))
        }
    }

    /// Machine output (notably NUL-delimited paths) must not be trimmed.
    #[cfg(unix)]
    pub fn run_raw(&self, argv: &[String]) -> Result<String> {
        validate_command(argv)?;
        Ok(String::from_utf8(self.run_unix_bytes(argv, true)?)?)
    }

    #[cfg(not(unix))]
    pub fn run_raw(&self, _argv: &[String]) -> Result<String> {
        Err(failure("Moon execution requires the verified Unix backend"))
    }

    #[cfg(unix)]
    fn run_unix_bytes(&self, argv: &[String], capture: bool) -> Result<Vec<u8>> {
        let started = Instant::now();
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&self.root)
            .env_clear()
            .envs(&self.environment);
        command
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .stdout(if capture {
                Stdio::piped()
            } else {
                Stdio::inherit()
            });
        let mut command = CommandWrap::from(command);
        #[cfg(unix)]
        command.wrap(process_wrap::std::ProcessGroup::leader());
        let mut child = OwnedChild(command.spawn()?);
        let reader = if capture {
            let stdout = child
                .0
                .stdout()
                .take()
                .ok_or_else(|| failure("Missing captured stdout"))?;
            let (send, receive) = mpsc::channel();
            thread::spawn(move || {
                let mut bytes = Vec::new();
                let result = stdout
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes);
                let _ = send.send(result);
            });
            Some(receive)
        } else {
            None
        };
        let status = loop {
            if INTERRUPTED.load(Ordering::SeqCst) || Instant::now() >= self.deadline {
                #[cfg(unix)]
                {
                    let _ = child.0.signal(15);
                    // The wrapped task is an executor with its own TERM to KILL
                    // grace (10 s) for the process tree it owns. Waiting less
                    // than that would kill it before its cleanup finishes and
                    // orphan the task's descendants.
                    let grace = Instant::now() + Duration::from_secs(20);
                    while Instant::now() < grace {
                        if child.0.try_wait()?.is_some() {
                            break;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                }
                let _ = child.0.start_kill();
                let _ = child.0.wait();
                return Err(failure(
                    "Command interrupted or timed out; its owned process group was terminated",
                ));
            }
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            thread::sleep(Duration::from_millis(20));
        };
        // Do not let detached descendants retain pipes or the shared project cache.
        let _ = child.0.start_kill();
        self.command_event(
            json!({"event":"command", "executable":Path::new(&argv[0]).file_name().map(|s|s.to_string_lossy()), "seconds":started.elapsed().as_secs_f64(), "exit_code":status.code()}),
        );
        if !status.success() {
            return Err(failure(format!(
                "{} failed: {status}",
                Path::new(&argv[0])
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            )));
        }
        if let Some(reader) = reader {
            let bytes = reader.recv_timeout(Duration::from_secs(10)).map_err(|_| {
                failure("Captured output did not close after command termination")
            })??;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(failure("Captured command output exceeded 16 MiB"));
            }
            return Ok(bytes);
        }
        Ok(Vec::new())
    }
}
