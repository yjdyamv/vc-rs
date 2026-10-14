//! Serving a mounted volume without a terminal: the background half of
//! `vcrs mount --letter Y`.
//!
//! `vcrs mount` without `--letter` serves in the foreground, which is right when
//! the user still has to type the two `iscsicli` commands into a second window:
//! Ctrl-C there stops the target, and there is nothing to look for later. A mount
//! with `--letter Y` is *finished* by the time the command returns — Windows has
//! the disk and the volume is on `Y:` — so holding the terminal open serves no
//! purpose and costs the user their shell. The target is handed to a detached
//! copy of this program instead and the prompt comes back; the volume stays
//! mounted until `vcrs dismount` (or until the initiator logs out and the
//! target's idle timeout runs out).
//!
//! A detached server has to be findable again, so the process that starts one
//! records it in a small state file in the temporary directory
//! (`vcrs-<iqn>.server`, holding the pid and the log). `vcrs dismount` then
//! stops the exact process that was started for that volume instead of guessing
//! at process names — and it does that *after* the logout, because until then
//! the session needs the target.

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::attach::Report;

/// The line `vcrs mount` prints once the target accepts logins. Waiting for it
/// is how the parent knows the background server is up.
const READY: &str = "iSCSI target ready";

/// How long the background server may take to come up (~25 s is the slow case:
/// a 500 000-iteration KDF on a cold cache).
const READY_WAIT: Duration = Duration::from_secs(90);

const POLL: Duration = Duration::from_millis(200);

/// How long to wait for a detached server to stop by itself after its last
/// session is gone before it is killed. The server's own idle time-out is three
/// seconds (`serve::spawn` passes `--idle-timeout 3` when the user chose none),
/// and the session is logged out before this is called, so three seconds is a
/// full turn of that clock rather than a hopeful guess.
const STOP_WAIT: Duration = Duration::from_secs(3);

/// A serving process this program started, and can find again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Server {
    pub iqn: String,
    pub pid: u32,
    pub log: PathBuf,
    /// The drive letter the volume was mounted on, so `vcrs dismount --letter`
    /// finds this server even after its session is gone.
    pub letter: Option<char>,
}

impl Server {
    /// The log file the detached process writes to (it has no console of its
    /// own, so this is where its output goes).
    fn log_path(iqn: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vcrs-{}.log", slug(iqn)))
    }

    /// Where this server is recorded so `vcrs dismount` can find it.
    fn state_path(iqn: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vcrs-{}.server", slug(iqn)))
    }
}

/// A file-name-safe form of an IQN (`iqn.2025-12.io.vcrs:secret`).
fn slug(iqn: &str) -> String {
    iqn.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Start a detached copy of this program that serves the volume, and wait until
/// its target is up.
///
/// The child runs *this same command* without the options that only make sense
/// in the foreground (`--letter`, `--foreground`) and with the target name and
/// the portal pinned to what the parent already computed — so the process is
/// recognisable even if the container is moved later, and two mounted volumes do
/// not fight over the same port. The password goes in over a pipe rather than on
/// the command line, so it does not end up in a second process's arguments.
pub(crate) fn spawn(
    iqn: &str,
    password: &[u8],
    letter: Option<char>,
    bind: &str,
    report: &mut Report,
) -> Result<Server> {
    let exe = std::env::current_exe().context("finding this program's own path")?;
    let args = child_arguments(iqn, bind, std::env::args_os())?;
    let log = Server::log_path(iqn);
    let file = fs::File::create(&log)
        .with_context(|| format!("creating the background log {}", log.display()))?;
    disinherit_standard_handles();

    let mut command = Command::new(&exe);
    command
        .args(&args)
        // The child is told the password over stdin; an inherited
        // `VCRS_PASSWORD` would collide with `--password-stdin`.
        .env_remove("VCRS_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // No console at all, and a process group of its own: closing the
        // terminal (or Ctrl-C in it) must not take the volume down.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("starting {} as a background server", exe.display()))?;
    let mut server = Server {
        iqn: iqn.to_string(),
        pid: child.id(),
        log,
        letter,
    };

    // The password, and nothing else: `--password-stdin` reads to end of file.
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(password)
            .context("giving the background server the password")?;
        stdin.flush().ok();
        // Dropped here, which closes the pipe.
    }

    report.line(&format!(
        "serving in the background (pid {}, log {})",
        server.pid,
        server.log.display()
    ));

    if let Err(err) = wait_until_ready(&server, &mut child) {
        // Nothing is served by a server that never came up.
        let _ = child.kill();
        return Err(err);
    }
    // The handle goes, the process stays: `Child` does not kill on drop.
    drop(child);
    server.iqn = iqn.to_string();
    Ok(server)
}

/// Wait until the detached server's target accepts logins.
pub(crate) fn wait_until_ready(server: &Server, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + READY_WAIT;
    loop {
        if read_log(&server.log).contains(READY) {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "the background server stopped before its target was ready ({status}):\n{}",
                tail(&server.log)
            );
        }
        if Instant::now() >= deadline {
            bail!(
                "the background server did not have its target up within {} s:\n{}",
                READY_WAIT.as_secs(),
                tail(&server.log)
            );
        }
        std::thread::sleep(POLL);
    }
}

/// The size of the disk the target presents, read out of the server's log
/// (`serving … as a 11272192 byte disk`), so the attach can tell its own disk
/// from any other vc-rs volume that is already mounted.
pub(crate) fn disk_size(server: &Server) -> Option<u64> {
    let text = read_log(&server.log);
    let at = text.find(" byte disk")?;
    let head = &text[..at];
    let digits: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<char>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// Record a server that is serving a mounted volume, so `vcrs dismount` can stop
/// it again.
pub(crate) fn remember(server: &Server) -> Result<()> {
    let state = Server::state_path(&server.iqn);
    // The IQN is written out in full: the file name is a slug (the `:` of an IQN
    // cannot be part of a path), so it can only ever be a fallback for state files
    // written before this line existed.
    let mut text = format!(
        "iqn={}\npid={}\nlog={}\n",
        server.iqn,
        server.pid,
        server.log.display()
    );
    if let Some(letter) = server.letter {
        text.push_str(&format!("letter={letter}\n"));
    }
    fs::write(&state, text).with_context(|| format!("writing {}", state.display()))?;
    Ok(())
}

/// The server recorded for `iqn`, if it has not been stopped already.
pub(crate) fn state(iqn: &str) -> Option<Server> {
    read_state(&Server::state_path(iqn))
}

/// Every server still recorded, newest state files included.
pub(crate) fn states() -> Vec<Server> {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("vcrs-") && name.ends_with(".server") {
            if let Some(server) = read_state(&entry.path()) {
                out.push(server);
            }
        }
    }
    out.sort_by(|a, b| a.iqn.cmp(&b.iqn));
    out
}

/// The server a state file describes. The file is the source of truth: the
/// slugged file name cannot be turned back into an IQN exactly.
fn read_state(path: &std::path::Path) -> Option<Server> {
    let text = fs::read_to_string(path).ok()?;
    let mut pid = None;
    let mut log = None;
    let mut iqn = None;
    let mut letter = None;
    for line in text.lines() {
        match line.split_once('=') {
            Some(("pid", value)) => pid = value.trim().parse::<u32>().ok(),
            Some(("log", value)) => log = Some(PathBuf::from(value.trim())),
            Some(("iqn", value)) => iqn = Some(value.trim().to_string()),
            Some(("letter", value)) => letter = value.trim().chars().next(),
            _ => {}
        }
    }
    let iqn = iqn.or_else(|| {
        path.file_stem().and_then(|stem| {
            stem.to_string_lossy()
                .strip_prefix("vcrs-")
                .map(str::to_string)
        })
    })?;
    Some(Server {
        iqn,
        pid: pid?,
        log: log.unwrap_or_else(|| Server::log_path("")),
        letter,
    })
}

/// Forget a server's state file (after it went away, or after it was stopped).
pub(crate) fn forget(iqn: &str) {
    let _ = fs::remove_file(Server::state_path(iqn));
}

/// Stop a background server, waiting first: the target often ends by itself a
/// few seconds after its last session is logged out.
pub(crate) fn stop(server: &Server, report: &mut Report) -> bool {
    let script = format!(
        "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; \
         if (!$p) {{ 'gone' }} else {{ \
         for ($i = 0; $i -lt {} -and !$p.HasExited; $i++) {{ Start-Sleep -Milliseconds 500 }}; \
         if ($p.HasExited) {{ 'exited' }} else {{ $p | Stop-Process -Force; 'killed' }} }}",
        server.pid,
        STOP_WAIT.as_millis() / 500
    );
    let outcome = match crate::attach::powershell(&script) {
        Ok(text) => text.trim().to_string(),
        Err(err) => {
            report.line(&format!(
                "could not ask Windows about the background server (pid {}): {err:#}",
                server.pid
            ));
            String::new()
        }
    };
    forget(&server.iqn);
    match outcome.as_str() {
        "gone" => {
            report.line(&format!(
                "the background server (pid {}) had already stopped",
                server.pid
            ));
            true
        }
        "exited" => {
            report.line(&format!(
                "the background server (pid {}) stopped",
                server.pid
            ));
            true
        }
        "killed" => {
            report.line(&format!(
                "the background server (pid {}) would not stop and was killed",
                server.pid
            ));
            true
        }
        other => {
            report.line(&format!(
                "could not stop the background server (pid {}): {}",
                server.pid,
                if other.is_empty() { "no answer" } else { other }
            ));
            false
        }
    }
}

/// This program's own `mount` arguments, minus what only the foreground wants,
/// plus the pinned target name, the pinned portal and `--password-stdin`.
fn child_arguments(
    iqn: &str,
    bind: &str,
    mut iter: impl Iterator<Item = OsString>,
) -> Result<Vec<OsString>> {
    let _exe = iter.next();
    let subcommand = iter.next();
    if subcommand.as_deref() != Some(std::ffi::OsStr::new("mount")) {
        bail!("the background server can only be started from `vcrs mount`");
    }
    let mut out: Vec<OsString> = vec![subcommand.expect("checked above")];
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy().to_string();
        match text.as_str() {
            // The drive letter is dealt with by the parent, and a child that
            // also asked for it would fight over the same session.
            "--letter" | "--foreground" | "--password" | "-p" | "--target-name" | "--bind" => {
                let _ = iter.next();
            }
            "--password-stdin" => {}
            _ if text.starts_with("--letter=")
                || text.starts_with("--password=")
                || text.starts_with("--target-name=")
                || text.starts_with("--bind=") =>
            {
                // Skip: the value is inside this argument.
            }
            _ => out.push(arg),
        }
    }
    // The parent's summary promises the volume stays mounted until `vcrs
    // dismount`, so the background server should not linger long after its
    // session is gone: three seconds is enough for the rescan the default
    // grace period exists for, and it keeps the dismount from waiting on a
    // process that is about to exit anyway.
    if !out
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with("--idle-timeout"))
    {
        out.push(OsString::from("--idle-timeout"));
        out.push(OsString::from("3"));
    }
    out.push(OsString::from("--target-name"));
    out.push(OsString::from(iqn));
    out.push(OsString::from("--bind"));
    out.push(OsString::from(bind));
    out.push(OsString::from("--password-stdin"));
    Ok(out)
}

/// Stop this process's console handles from being inherited by the detached
/// server.
///
/// A child created with handle inheritance receives **every** inheritable handle
/// the parent holds — and when `vcrs mount --letter` runs under a shell, the
/// shell's end of the console pipe is one of them. The shell then waits for a
/// pipe that the detached server holds open, so the prompt never comes back even
/// though the volume is mounted. The child's own stdout is the log file, so
/// nothing here is of any use to it.
#[cfg(windows)]
fn disinherit_standard_handles() {
    use winapi::um::handleapi::{SetHandleInformation, INVALID_HANDLE_VALUE};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    /// `HANDLE_FLAG_INHERIT`, which winapi does not export for `um::winnt`.
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(which) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // Best effort: a handle that cannot be changed is not worth failing over.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
}

#[cfg(not(windows))]
fn disinherit_standard_handles() {}

/// The log, or an empty string while it does not exist yet.
fn read_log(path: &std::path::Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// The last few lines of a log, for an error message.
fn tail(path: &std::path::Path) -> String {
    let text = read_log(path);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(6);
    if lines.is_empty() {
        return "    (the log is empty)".to_string();
    }
    lines[start..]
        .iter()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(argv: &[&str]) -> Vec<OsString> {
        let mut out = vec![OsString::from("vcrs.exe"), OsString::from("mount")];
        out.extend(argv.iter().map(OsString::from));
        out
    }

    #[test]
    fn the_child_serves_the_same_volume_without_the_drive_letter() {
        let input = args(&[
            "secret.vc",
            "--password",
            "hunter2",
            "--letter",
            "Y",
            "--removable",
            "--idle-timeout",
            "30",
        ]);
        let child = child_arguments(
            "iqn.2025-12.io.vcrs:secret",
            "127.0.0.1:3260",
            input.into_iter(),
        )
        .expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(
            text,
            vec![
                "mount",
                "secret.vc",
                "--removable",
                "--idle-timeout",
                "30",
                "--target-name",
                "iqn.2025-12.io.vcrs:secret",
                "--bind",
                "127.0.0.1:3260",
                "--password-stdin",
            ]
        );
    }

    #[test]
    fn a_pinned_target_name_is_replaced_not_duplicated() {
        let input = args(&["secret.vc", "--target-name", "iqn.old", "--foreground"]);
        let child =
            child_arguments("iqn.new", "127.0.0.1:3260", input.into_iter()).expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(text.iter().filter(|arg| *arg == "--target-name").count(), 1);
        assert!(text.contains(&"iqn.new".to_string()));
        assert!(!text.contains(&"iqn.old".to_string()));
        assert!(!text.contains(&"--foreground".to_string()));
    }

    #[test]
    fn an_equals_style_option_is_dropped_too() {
        let input = args(&["secret.vc", "--letter=Y", "--password=hunter2"]);
        let child =
            child_arguments("iqn.x", "127.0.0.1:3260", input.into_iter()).expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(
            text,
            vec![
                "mount",
                "secret.vc",
                "--idle-timeout",
                "3",
                "--target-name",
                "iqn.x",
                "--bind",
                "127.0.0.1:3260",
                "--password-stdin",
            ]
        );
    }

    #[test]
    fn a_chosen_idle_timeout_is_left_alone() {
        let input = args(&["secret.vc", "--idle-timeout", "0"]);
        let child =
            child_arguments("iqn.x", "127.0.0.1:3260", input.into_iter()).expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(
            text.iter().filter(|arg| *arg == "--idle-timeout").count(),
            1
        );
        assert!(text.contains(&"0".to_string()));
    }

    #[test]
    fn the_disk_size_comes_out_of_the_log() {
        let server = Server {
            iqn: "iqn.x".to_string(),
            pid: 1,
            log: std::env::temp_dir().join("vcrs-serve-size-test.log"),
            letter: None,
        };
        fs::write(
            &server.log,
            "serving secret.vc (10223616 bytes of data area, 512 byte sectors, partitioned) \
             as a 11272192 byte disk\niSCSI target ready: iqn.x on 127.0.0.1:3260\n",
        )
        .expect("write");
        assert_eq!(disk_size(&server), Some(11272192));
        let _ = fs::remove_file(&server.log);
    }

    #[test]
    fn a_state_file_is_read_back_from_the_iqn_or_from_its_name() {
        let dir = std::env::temp_dir().join("vcrs-serve-state-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("vcrs-iqn.2025-12.io.vcrs_secret.server");
        fs::write(
            &path,
            "pid=4242\nlog=C:\\Temp\\vcrs.log\niqn=iqn.2025-12.io.vcrs:secret\nletter=Y\n",
        )
        .expect("write");
        let server = read_state(&path).expect("a server");
        assert_eq!(server.pid, 4242);
        assert_eq!(server.iqn, "iqn.2025-12.io.vcrs:secret");
        assert_eq!(server.log, PathBuf::from("C:\\Temp\\vcrs.log"));
        assert_eq!(server.letter, Some('Y'));

        fs::write(&path, "pid=7\n").expect("write");
        let server = read_state(&path).expect("a server");
        assert_eq!(server.pid, 7);
        assert_eq!(server.iqn, "iqn.2025-12.io.vcrs_secret");
        assert_eq!(server.letter, None);
        let _ = fs::remove_dir_all(&dir);
    }
}
