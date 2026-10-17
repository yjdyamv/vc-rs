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
#[cfg(not(windows))]
use std::path::Path;
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
/// session is gone before it is killed. The server's own idle time-out is thirty
/// seconds (`serve::spawn` passes `--idle-timeout 30` when the user chose none),
/// and the session is logged out before this is called, so this is only the last
/// turn of that clock rather than a hopeful guess.
pub const STOP_WAIT: Duration = Duration::from_secs(2);

/// A serving process this program started, and can find again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
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
        state_dir().join(format!("vcrs-{}.log", slug(iqn)))
    }

    /// Where this server is recorded so `vcrs dismount` can find it.
    fn state_path(iqn: &str) -> PathBuf {
        state_dir().join(format!("vcrs-{}.server", slug(iqn)))
    }
}

/// The directory the servers' state files and logs live in.
///
/// This used to be `std::env::temp_dir()`, which is `%TEMP%` on Windows: every
/// process of every user can create files there, and by default they can read
/// each other's. Both halves of that are wrong for these files. A state file
/// planted there is what let an elevated `vcrs dismount` be pointed at an
/// unrelated process (see [`wait_and_kill`]), and a log there keeps the name of
/// the container on disk for anyone who comes by. The per-user application data
/// directory inherits the profile's access control list instead, so another user
/// can neither read the log nor plant a state file, and the `%TEMP%` cleaner that
/// runs on reboot or logon no longer takes a running server's files away.
///
/// It is created on demand, and the old temporary directory is used as a last
/// resort rather than failing a mount (a service account may have neither).
pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    // `$XDG_RUNTIME_DIR` is private to the user by definition; without it the
    // temporary directory is all we have, but the subdirectory is then 0700.
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_CACHE_HOME"))
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| Path::new(&home).join(".cache"))
        });
    let dir = base
        .unwrap_or_else(std::env::temp_dir)
        .join("vcrs");
    if !dir.is_dir() {
        let _ = create_private_dir(&dir);
    }
    dir
}

#[cfg(unix)]
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}

/// Create (or truncate) one of these files so that, on Unix, nobody else can
/// read it. Windows inherits the directory's access control list.
pub(crate) fn private_file(path: &std::path::Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
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
/// The tag that tells the framed stdin payload from a password that simply *is*
/// all of stdin. The CLI reads the same constant, so the two cannot drift apart.
pub const STDIN_SECRETS_TAG: &str = "vcrs-stdin-secrets v1";

/// Hex, for the framed stdin payload: a password may contain a newline, which is
/// what a line-per-secret payload would otherwise lose.
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn spawn(
    iqn: &str,
    secrets: &[&[u8]],
    letter: Option<char>,
    bind: &str,
    report: &mut Report,
) -> Result<Server> {
    let exe = std::env::current_exe().context("finding this program's own path")?;
    let args = child_arguments(iqn, bind, std::env::args_os())?;
    let log = Server::log_path(iqn);
    let file = private_file(&log)
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
    // This process writes what it says to a file that outlives the command, and at the
    // default level that includes `opened V2Hidden volume with PRF … and AES` — a line
    // that says a hidden volume exists, which is the one thing it exists to hide. Nobody
    // asking for `RUST_LOG` gets overruled; without it the file keeps warnings and errors
    // only, and the handshake line the parent waits for is printed straight to stderr and
    // is not affected by the filter.
    if std::env::var_os("RUST_LOG").is_none() {
        command.env("RUST_LOG", "warn");
    }

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

    // The secrets are framed rather than sent raw: the hidden volume's password has
    // to reach the child as well, one stdin cannot be read twice, and neither
    // password may go back into an argument list (see [`child_arguments`]).
    if let Some(mut stdin) = child.stdin.take() {
        let mut payload = String::from(STDIN_SECRETS_TAG);
        payload.push('\n');
        for secret in secrets {
            payload.push_str(&hex_encode(secret));
            payload.push('\n');
        }
        stdin
            .write_all(payload.as_bytes())
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
pub fn wait_until_ready(server: &Server, child: &mut Child) -> Result<()> {
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
pub fn disk_size(server: &Server) -> Option<u64> {
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
pub fn remember(server: &Server) -> Result<()> {
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
pub fn state(iqn: &str) -> Option<Server> {
    read_state(&Server::state_path(iqn))
}

/// Every server still recorded, newest state files included.
pub fn states() -> Vec<Server> {
    let Ok(entries) = fs::read_dir(state_dir()) else {
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
            Some(("log", value)) => {
                let value = PathBuf::from(value.trim());
                // The state file is written by this program but read back from a
                // directory other processes may reach, so its `log=` line is
                // attacker-controlled input. Without this check a planted file would
                // make every error message read (and print the tail of) an arbitrary
                // file — `C:\Windows\System32\config\SAM`, say.
                if in_state_dir(&value) {
                    log = Some(value);
                }
            }
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

/// Whether a path is inside this program's own state directory.
///
/// The state files (and the logs they name) are only ever written there, so a path
/// that points somewhere else was planted. The canonical check is what rejects a
/// `%LOCALAPPDATA%\vcrs\..\..\Windows\...` that starts out looking like one of ours.
fn in_state_dir(path: &std::path::Path) -> bool {
    let dir = state_dir();
    if !path.starts_with(&dir) {
        return false;
    }
    match (path.canonicalize(), dir.canonicalize()) {
        (Ok(path), Ok(dir)) => path.starts_with(&dir),
        // A log that was already deleted (or a directory we cannot resolve) cannot be
        // followed anywhere, so the lexical answer stands.
        _ => true,
    }
}

/// Forget a server's state file (after it went away, or after it was stopped).
///
/// Its log goes with it: the log names the container (the default target name is
/// derived from the file name), so leaving it on disk leaves the name of an
/// encrypted volume behind after the volume was dismounted. It is only removed
/// when it really is one of ours — the path comes from the state file, and
/// removing whatever it named would be an arbitrary file deletion.
pub fn forget(iqn: &str) {
    if let Some(server) = read_state(&Server::state_path(iqn)) {
        if in_state_dir(&server.log) {
            let _ = fs::remove_file(&server.log);
        }
    }
    let _ = fs::remove_file(Server::state_path(iqn));
}

/// Remove the logs of servers that nothing records any more.
///
/// A server that was killed or that went down with the machine leaves its log in
/// the state directory without a state file beside it, and that log is a lasting
/// record: it names the target, and under `RUST_LOG=debug` it says which layout was
/// opened — the one
/// thing a hidden volume exists to keep out of the open. A server that is still running
/// always has its state file (`remember` writes it right after `spawn`), so a log
/// without one belongs to nobody. Logs of an *attach* run (`vcrs-attach-<pid>.log`) are
/// kept until they are well past the five minutes an attach may take, because one may be
/// in flight right now and deleting it would lose that run's output.
pub fn sweep_logs() {
    // The temporary directory is swept as well: that is where these files lived
    // before, so an older build (or a machine that was not cleaned since) still
    // has the container's name lying there.
    let mut dirs = vec![state_dir()];
    let legacy = std::env::temp_dir();
    if legacy != dirs[0] {
        dirs.push(legacy);
    }
    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        sweep_one_dir(&dir, entries);
    }
}

fn sweep_one_dir(dir: &std::path::Path, entries: fs::ReadDir) {
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        // A state file this build cannot read any more (it looks in `state_dir`), so
        // whatever it described is not reachable through `vcrs dismount` anyway.
        if name.starts_with("vcrs-") && name.ends_with(".server") && dir == std::env::temp_dir() && dir != state_dir() {
            let _ = fs::remove_file(&path);
            continue;
        }
        let Some(slug) = name
            .strip_prefix("vcrs-")
            .and_then(|rest| rest.strip_suffix(".log"))
        else {
            continue;
        };
        if slug.is_empty() {
            continue;
        }
        if slug.starts_with("attach-") {
            // `LOG_WAIT` gives an attach five minutes to speak; anything older than this
            // is a parent that died while waiting for its elevated half.
            const ATTACH_LOG_GRACE: Duration = Duration::from_secs(15 * 60);
            let stale = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|written| written.elapsed().ok())
                .is_some_and(|age| age > ATTACH_LOG_GRACE);
            if stale {
                let _ = fs::remove_file(&path);
            }
            continue;
        }
        if !Server::state_path(slug).exists() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Whether an open process handle is this program (a `vcrs.exe`).
///
/// State files are plain files whose `pid=` line the user can rewrite (and, back
/// when they lived in `%TEMP%`, so could every other process of every other user),
/// so that line is attacker-controlled input: without this check a planted
/// `vcrs-*.server` would turn `vcrs dismount` — which runs elevated, because it has
/// to touch disks and letters — into "terminate any process on this machine". The
/// image name is the strongest claim a handle can be asked for without reading the
/// command line, and it also refuses the ordinary accident of a state file that
/// outlived its server and a pid that got reused.
#[cfg(windows)]
unsafe fn is_this_program(handle: winapi::shared::ntdef::HANDLE) -> bool {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::winbase::QueryFullProcessImageNameW;

    let mut buf = [0u16; 260];
    let mut len: DWORD = buf.len() as DWORD;
    // `PROCESS_NAME_WIN32` (0) returns the Win32 path, without the terminator.
    if unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) } == 0 {
        // A process we cannot even name is not one we will end.
        return false;
    }
    let path = OsString::from_wide(&buf[..len as usize]);
    let Some(name) = std::path::Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
    else {
        return false;
    };
    // Compare against *this* program's own name rather than the literal
    // "vcrs.exe": the server is a copy of `std::env::current_exe()`, so a renamed
    // or rebuilt binary still matches, while an unrelated process does not. (The
    // check fails closed — a process it cannot recognise is left running, and
    // `dismount` says so instead of pretending it stopped it.)
    let ours = std::env::current_exe().ok().and_then(|exe| {
        exe.file_name()
            .map(|name| name.to_string_lossy().to_string())
    });
    ours.is_some_and(|ours| name.eq_ignore_ascii_case(&ours))
}

/// Stop a background server, waiting first: the target often ends by itself a
/// few seconds after its last session is logged out.
/// Wait for a process to exit, then kill it if it will not.
///
/// This used to be a PowerShell script (`Get-Process` + `Start-Sleep` loop +
/// `Stop-Process`), which cost a whole PowerShell start — 1.5 to 10 s on this
/// machine, and a console window before that — for a question the kernel answers
/// instantly. It returns the same three words the script printed.
pub fn wait_and_kill(pid: u32, timeout: Duration) -> &'static str {
    #[cfg(windows)]
    unsafe {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetExitCodeProcess, OpenProcess, TerminateProcess};
        use winapi::um::winnt::{PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

        // `STILL_ACTIVE` (259) lives in winapi's winbase feature; one number is not
        // worth a feature flag, so it is declared here.
        const STILL_ACTIVE: u32 = 259;

        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            pid,
        );
        if handle.is_null() {
            // It is gone (or somebody else owns it and we are not elevated, which
            // cannot happen here: the worker runs elevated).
            return "gone";
        }
        if !is_this_program(handle) {
            CloseHandle(handle);
            return "refused";
        }
        let deadline = std::time::Instant::now() + timeout;
        let mut code: u32;
        loop {
            code = 0;
            if GetExitCodeProcess(handle, &mut code) == 0 {
                break;
            }
            if code != STILL_ACTIVE {
                CloseHandle(handle);
                return "exited";
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        TerminateProcess(handle, 1);
        CloseHandle(handle);
        "killed"
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, timeout);
        "gone"
    }
}

pub fn stop(server: &Server, report: &mut Report) -> bool {
    // Asking Windows about a process is a kernel question, not a PowerShell one.
    let outcome = wait_and_kill(server.pid, STOP_WAIT).to_string();
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
        "refused" => {
            report.line(&format!(
                "the state file for {} names pid {}, which is not a vcrs server; it was left \
                 alone and the state file was dropped",
                server.iqn, server.pid
            ));
            false
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
fn is_secret_argument(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    lower.contains("password") || lower.contains("secret") || lower.contains("master-key")
}

/// This program's own `mount` arguments, minus what only the foreground wants,
/// plus the pinned target name, the pinned portal and the stdin secrets.
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
    // With hidden-volume protection the child needs the hidden password too, and
    // the only way left to hand it over is the pipe.
    let mut protect_hidden = false;
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy().to_string();
        if text == "--protect-hidden" {
            protect_hidden = true;
        }
        match text.as_str() {
            // The drive letter is dealt with by the parent, and a child that
            // also asked for it would fight over the same session.
            "--letter" | "--target-name" | "--bind" => {
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
    // session is gone: three seconds is enough for the rescan the default
    // grace period exists for, and it keeps the dismount from waiting on a
    // process that is about to exit anyway.
    if !out
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with("--idle-timeout"))
    {
        out.push(OsString::from("--idle-timeout"));
        // Long enough to ride out the initiator dropping and re-establishing its
        // connection a second after the login (the log shows `Connection closed`
        // right after `FullFeaturePhase`); with three seconds the server used to
        // walk away in the middle of its own attach, and the mount then failed
        // with `Windows did not show the disk`. Once the volume is mounted the
        // session stays connected, so this grace period is never reached.
        out.push(OsString::from("30"));
    }
    out.push(OsString::from("--target-name"));
    out.push(OsString::from(iqn));
    out.push(OsString::from("--bind"));
    out.push(OsString::from(bind));
    // The parent only lets a non-loopback bind through when the user asked for it
    // (`--allow-remote`), so the child has to be told the same thing — it re-runs
    // the same validation on the arguments it is given.
    if !crate::attach::is_loopback_addr(bind) {
        out.push(OsString::from("--allow-remote"));
    }
    out.push(OsString::from("--password-stdin"));
    if protect_hidden {
        out.push(OsString::from("--hidden-password-stdin"));
    }
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
pub fn disinherit_standard_handles() {
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
pub fn disinherit_standard_handles() {}

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
    fn no_secret_reaches_the_child_through_its_arguments() {
        // Every shape a password can take in `vcrs mount`'s arguments: the long
        // form (which the old list missed), the alias, the attached short form,
        // and both `=` styles. The hidden password must arrive over the pipe, so
        // `--hidden-password-stdin` is added in its place.
        let input = args(&[
            "secret.vc",
            "--protect-hidden",
            "--hidden-password",
            "hunter2",
            "--hidden-pim",
            "10",
            "--hidden-keyfile",
            "k.bin",
            "--read-only",
        ]);
        let child =
            child_arguments("iqn.x", "127.0.0.1:3260", input.into_iter()).expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert!(!text.iter().any(|arg| arg.contains("hunter2")), "{text:?}");
        assert!(text.contains(&"--protect-hidden".to_string()));
        assert!(text.contains(&"--hidden-password-stdin".to_string()));
        // Everything that is not a secret still gets through.
        assert!(text.contains(&"--hidden-pim".to_string()));
        assert!(text.contains(&"10".to_string()));
        assert!(text.contains(&"--hidden-keyfile".to_string()));
        assert!(text.contains(&"k.bin".to_string()));
        assert!(text.contains(&"--read-only".to_string()));

        // The main password, all four ways. None of them may leave a stray token.
        for form in [
            vec!["secret.vc", "-p", "hunter2"],
            vec!["secret.vc", "-phunter2"],
            vec!["secret.vc", "--password", "hunter2"],
            vec!["secret.vc", "--password=hunter2"],
            vec!["secret.vc", "--master-key", "00ff"],
        ] {
            let child = child_arguments("iqn.x", "127.0.0.1:3260", args(&form).into_iter())
                .expect("arguments");
            let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
            assert!(!text.iter().any(|arg| arg.contains("hunter2")), "{form:?} {text:?}");
            assert!(!text.iter().any(|arg| arg.contains("00ff")), "{form:?} {text:?}");
            // The container itself is not a secret, and it has to survive.
            assert!(text.contains(&"secret.vc".to_string()), "{form:?} {text:?}");
            assert!(!text.contains(&"--hidden-password-stdin".to_string()));
            assert_eq!(
                text,
                vec![
                    "mount",
                    "secret.vc",
                    "--idle-timeout",
                    "30",
                    "--target-name",
                    "iqn.x",
                    "--bind",
                    "127.0.0.1:3260",
                    "--password-stdin",
                ],
                "{form:?}"
            );
        }
    }

    #[test]
    fn a_switch_does_not_swallow_the_container() {
        let input = args(&[
            "secret.vc",
            "--foreground",
            "--letter",
            "Y",
            "--password-stdin",
        ]);
        let child = child_arguments("iqn.x", "127.0.0.1:3260", input.into_iter())
            .expect("arguments");
        let text: Vec<String> = child.iter().map(|a| a.to_string_lossy().into()).collect();
        assert_eq!(
            text,
            vec![
                "mount",
                "secret.vc",
                "--idle-timeout",
                "30",
                "--target-name",
                "iqn.x",
                "--bind",
                "127.0.0.1:3260",
                "--password-stdin",
            ],
            "{text:?}"
        );
    }

    #[test]
    fn the_stdin_payload_survives_a_password_with_a_newline() {
        let secret: Vec<u8> = b"one\ntwo".to_vec();
        let payload = format!("{}\n{}\n", STDIN_SECRETS_TAG, hex_encode(&secret));
        let mut lines = payload.split('\n');
        assert_eq!(lines.next(), Some(STDIN_SECRETS_TAG));
        assert_eq!(hex_encode(&secret), lines.next().expect("one line"));
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
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
                "30",
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
            log: state_dir().join("vcrs-serve-size-test.log"),
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
        let dir = state_dir().join("vcrs-serve-state-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("vcrs-iqn.2025-12.io.vcrs_secret.server");
        // The log path is taken from the file, so it has to point where a log really
        // is written; `read_state` drops a path from anywhere else.
        let log = state_dir().join("vcrs-serve-state-test.log");
        fs::write(
            &path,
            format!(
                "pid=4242\nlog={}\niqn=iqn.2025-12.io.vcrs:secret\nletter=Y\n",
                log.display()
            ),
        )
        .expect("write");
        let server = read_state(&path).expect("a server");
        assert_eq!(server.pid, 4242);
        assert_eq!(server.iqn, "iqn.2025-12.io.vcrs:secret");
        assert_eq!(server.log, log);
        assert_eq!(server.letter, Some('Y'));

        // A `log=` that points outside the temporary directory is not followed.
        fs::write(&path, "pid=4242\nlog=C:\\Windows\\System32\\config\\SAM\n").expect("write");
        let server = read_state(&path).expect("a server");
        assert_eq!(server.log, Server::log_path(""));

        fs::write(&path, "pid=7\n").expect("write");
        let server = read_state(&path).expect("a server");
        assert_eq!(server.pid, 7);
        assert_eq!(server.iqn, "iqn.2025-12.io.vcrs_secret");
        assert_eq!(server.letter, None);
        let _ = fs::remove_dir_all(&dir);
    }
}
