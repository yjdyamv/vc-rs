//! Starting the background server, and framing the secrets it is handed.
//!
//! A mount that outlives the command that started it needs a second process:
//! the foreground `vcrs mount` serves the volume over iSCSI and stays in the
//! terminal, while `vcrs mount --letter` (Windows) and every `vcrs mount` on
//! Linux hand the volume to a *detached* copy of this program and return as soon
//! as the initiator has the disk. That copy is the same command line with the
//! options that only make sense in the foreground removed and with the target
//! name and portal pinned to what the parent computed.
//!
//! The password never goes on that command line: the child reads it from its
//! stdin, so it does not end up in a second process's arguments (where task
//! managers, ETW and audit logs can read it) and does not survive in the shell
//! history of the parent.

use std::ffi::OsString;
#[cfg(unix)]
use std::path::Path;

use crate::{Error, Result};

/// The tag that tells the framed stdin payload from a password that simply *is*
/// all of stdin. The CLI reads the same constant, so the two cannot drift apart.
pub const STDIN_SECRETS_TAG: &str = "vcrs-stdin-secrets v1";

/// Hex, for the framed stdin payload: a password may contain a newline, which is
/// what a line-per-secret payload would otherwise lose.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// The framed payload: the tag line, then one hex-encoded secret per line.
pub fn secrets_payload(secrets: &[&[u8]]) -> String {
    let mut out = String::with_capacity(STDIN_SECRETS_TAG.len() + 1 + secrets.len() * 66);
    out.push_str(STDIN_SECRETS_TAG);
    out.push('\n');
    for secret in secrets {
        out.push_str(&hex_encode(secret));
        out.push('\n');
    }
    out
}

/// Whether an *option* names a secret that must not be copied into a second,
/// long-lived process's command line.
///
/// This is a *rule* rather than a list of flag names on purpose. The list this
/// replaces missed `--hidden-password`, `--protection-password` and the attached
/// `-phunter2` form, and a list is a thing that goes stale the next time a flag is
/// added; "no password goes into an argument" does not. Only option-like
/// arguments are considered: a *container* may well be called `secret.vc`.
/// (`--password-stdin` and friends match too and are dropped, because the parent
/// adds its own back.)
pub fn is_secret_argument(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    lower.contains("password") || lower.contains("secret") || lower.contains("master-key")
}

/// This program's own `mount` arguments, minus what only the foreground wants,
/// plus the pinned target name, the pinned portal and the stdin secrets.
///
/// `--letter` (Windows) and `--mount-point` (Linux) are dealt with by the parent,
/// and a child that asked for them too would fight over the same session.
pub fn child_arguments(
    iqn: &str,
    bind: &str,
    mut iter: impl Iterator<Item = OsString>,
) -> Result<Vec<OsString>> {
    let _exe = iter.next();
    let subcommand = iter.next();
    if subcommand.as_deref() != Some(std::ffi::OsStr::new("mount")) {
        return Err(Error::InvalidParameter(
            "the background server can only be started from `vcrs mount`".to_string(),
        ));
    }
    let mut out: Vec<OsString> = vec![subcommand.expect("checked above")];
    // With hidden-volume protection the child needs the hidden password too, and
    // the only way left to hand it over is the pipe.
    let mut protect_hidden = false;
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy().to_string();
        if text == "--protect-hidden" {
            protect_hidden = true;
        }
        match text.as_str() {
            "--letter" | "--mount-point" | "--target-name" | "--bind" => {
                let _ = iter.next();
            }
            // `--foreground` is a switch and takes no value, so the next argument
            // must not be swallowed with it. The old filter listed it with the
            // value-taking options and so ate the argument that followed it —
            // `vcrs mount --foreground secret.vc` lost the container.
            "--foreground" => {}
            // Both are re-added below, from the parent's own knowledge.
            "--password-stdin" | "--hidden-password-stdin" => {}
            // `-phunter2` is `--password hunter2` in one token, and bare `-p`
            // takes the next one.
            "-p" => {
                let _ = iter.next();
            }
            _ if text.starts_with("-p") && !text.starts_with("--") => {}
            _ if text.starts_with("--letter=")
                || text.starts_with("--mount-point=")
                || text.starts_with("--target-name=")
                || text.starts_with("--bind=") =>
            {
                // Skip: the value is inside this argument.
            }
            _ if text.starts_with('-') && is_secret_argument(&text) => {
                // A secret's value goes with it, or it would be left behind as a
                // stray positional — which clap would then read as the volume.
                if !text.contains('=') && !text.ends_with("-stdin") {
                    let _ = iter.next();
                }
            }
            _ => out.push(arg),
        }
    }
    // The parent's summary promises the volume stays mounted until `vcrs
    // dismount`, so the background server should not linger long after its
    // session is gone. The default grace period is long enough that the child
    // would outlive a broken attachment by minutes.
    if !out
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with("--idle-timeout"))
    {
        out.push(OsString::from("--idle-timeout"));
        // Long enough to ride out the initiator dropping and re-establishing its
        // connection right after the login (the log shows `Connection closed`
        // next to `FullFeaturePhase`); with three seconds the server used to walk
        // away in the middle of its own attach, and the mount then failed with
        // `Windows did not show the disk`. Once the volume is mounted the session
        // stays connected, so this grace period is never reached.
        out.push(OsString::from("30"));
    }
    out.push(OsString::from("--target-name"));
    out.push(OsString::from(iqn));
    out.push(OsString::from("--bind"));
    out.push(OsString::from(bind));
    // The parent only lets a non-loopback bind through when the user asked for it
    // (`--allow-remote`), so the child has to be told the same thing — it re-runs
    // the same validation on the arguments it is given.
    if !crate::net::is_loopback_addr(bind) {
        out.push(OsString::from("--allow-remote"));
    }
    out.push(OsString::from("--password-stdin"));
    if protect_hidden {
        out.push(OsString::from("--hidden-password-stdin"));
    }
    Ok(out)
}

/// Start this program again, detached from the terminal, and hand it its secrets
/// on stdin.
///
/// `args` is what [`child_arguments`] returned (without the program name). The
/// child is put in a session of its own, so the shell that started the mount can
/// exit, and Ctrl-C in it does not reach the server.
#[cfg(unix)]
/// A server that is running in its own session, with the handle kept so that a
/// caller can tell whether it is still alive.
#[cfg(unix)]
pub struct Detached {
    pub pid: u32,
    child: std::process::Child,
}

#[cfg(unix)]
impl Detached {
    /// The process id, for the state file and for `vcrs dismount`.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(unix)]
pub fn spawn_detached(args: &[OsString], secrets: &[&[u8]], log: &Path) -> Result<Detached> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().map_err(Error::Io)?;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir).map_err(Error::Io)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(log)
        .map_err(Error::Io)?;
    let err = file.try_clone().map_err(Error::Io)?;
    let mut command = Command::new(&exe);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(err))
        // The detaching child has no use for the caller's password in its
        // environment, and a long-lived process should not carry one.
        .env_remove("VCRS_PASSWORD");
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(Error::Io)?;
    let pid = child.id();
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            Error::InvalidParameter("the background server did not take its stdin".to_string())
        })?;
        stdin
            .write_all(secrets_payload(secrets).as_bytes())
            .map_err(Error::Io)?;
        stdin.flush().map_err(Error::Io)?;
    }
    // Closing the pipe is what tells the child the secrets are complete. Dropping
    // the handle does not signal the child: it is in its own session and keeps
    // serving until the initiator logs out.
    drop(child.stdin.take());
    Ok(Detached { pid, child })
}

/// Wait until the detached server has said it is serving.
///
/// The server prints its handshake line to the log, which is the only channel the
/// parent has (the child is detached and its stdout *is* that log).
#[cfg(unix)]
#[cfg(unix)]
pub fn wait_for_ready(
    detached: &mut Detached,
    log: &Path,
    ready: &str,
    timeout: std::time::Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            if text.contains(ready) {
                return Ok(());
            }
        }
        // A server that died on its own (a wrong password, a name that does not
        // exist) will never become ready, so do not sit out the whole timeout:
        // report what it said instead.
        if let Ok(Some(status)) = detached.child.try_wait() {
            let tail = last_lines(log, 8);
            return Err(Error::Unsupported(format!(
                "the background server exited before it was ready ({status}); it logged:\n{tail}"
            )));
        }
        if start.elapsed() >= timeout {
            let tail = last_lines(log, 8);
            let still_running = matches!(detached.child.try_wait(), Ok(None));
            let why = if still_running {
                "it is still running, so it is probably still unlocking the volume (a wrong password or PIM makes every layout, PRF and cipher be tried in turn)"
            } else {
                "it is not running any more"
            };
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "the background server did not come up within {} s; {why}; it logged:\n{tail}",
                    timeout.as_secs()
                ),
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The last `count` lines a server wrote, or a note saying it wrote nothing.
#[cfg(unix)]
fn last_lines(log: &Path, count: usize) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().rev().take(count).collect();
    let tail = lines.into_iter().rev().collect::<Vec<&str>>().join("\n");
    if tail.trim().is_empty() {
        "(nothing: the server exited before it printed anything)".to_string()
    } else {
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn child(list: &[&str]) -> Vec<String> {
        let parsed = child_arguments("iqn.2025-12.io.vcrs:test", "127.0.0.1:3260", args(list).into_iter())
            .expect("the arguments are valid");
        parsed
            .into_iter()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn the_mount_point_and_the_letter_stay_with_the_parent() {
        assert_eq!(
            child(&["vcrs", "mount", "v.vc", "--mount-point", "/mnt/v", "--letter", "Y"]),
            vec![
                "mount",
                "v.vc",
                "--idle-timeout",
                "30",
                "--target-name",
                "iqn.2025-12.io.vcrs:test",
                "--bind",
                "127.0.0.1:3260",
                "--password-stdin",
            ]
        );
    }

    #[test]
    fn the_options_the_server_needs_survive() {
        assert_eq!(
            child(&[
                "vcrs",
                "mount",
                "v.vc",
                "--hidden",
                "--pim",
                "12",
                "--read-only",
                "--no-preserve-timestamp",
            ]),
            vec![
                "mount",
                "v.vc",
                "--hidden",
                "--pim",
                "12",
                "--read-only",
                "--no-preserve-timestamp",
                "--idle-timeout",
                "30",
                "--target-name",
                "iqn.2025-12.io.vcrs:test",
                "--bind",
                "127.0.0.1:3260",
                "--password-stdin",
            ]
        );
    }

    #[test]
    fn a_secret_never_reaches_the_child_arguments() {
        for spelling in [
            vec!["-p", "hunter2"],
            vec!["-phunter2"],
            vec!["--password", "hunter2"],
            vec!["--password=hunter2"],
            vec!["--hidden-password", "hunter2"],
            vec!["--hidden-password=hunter2"],
            vec!["--master-key", "00ff"],
        ] {
            let mut list = vec!["vcrs", "mount", "secret.vc"];
            list.extend(spelling.iter().copied());
            let out = child(&list);
            assert!(
                !out.iter().any(|arg| arg.contains("hunter2") || arg.contains("00ff")),
                "{spelling:?} leaked into {out:?}"
            );
            assert_eq!(out[1], "secret.vc", "the container went missing: {out:?}");
        }
    }

    #[test]
    fn the_payload_is_tagged_and_hex_encoded() {
        assert_eq!(
            secrets_payload(&[b"one\ntwo", b""]),
            "vcrs-stdin-secrets v1\n6f6e650a74776f\n\n"
        );
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(hex_encode(b""), "");
    }
}
