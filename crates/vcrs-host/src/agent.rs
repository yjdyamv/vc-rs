//! A cached elevated helper: the iSCSI work needs administrator, and asking for
//! it once per command is one prompt too many.
//!
//! The elevated half of `vcrs attach`/`vcrs detach` is the only part of this
//! program that needs administrator: `iscsicli` carries a `requireAdministrator`
//! manifest, and taking a disk offline or logging an iSCSI session out needs the
//! same rights. Windows has no way to raise a process that is already running, so
//! the first such command asks for a prompt — and the elevated process that
//! answers it also leaves an agent behind. The agent listens on a named pipe;
//! later commands hand it the same words they would have given an elevated child,
//! and it runs them with no prompt at all. It ends itself after ten minutes with
//! no requests, and `vcrs agent --stop` ends it at once.
//!
//! Three things keep the arrangement honest:
//!
//! - The pipe is created by an elevated process, so it keeps the default DACL of
//!   that process token: the same user and the administrators, nobody else.
//!   `\\.\pipe\` is local-only in any case.
//! - Only `vcrs attach` and `vcrs detach` are run. The agent is a way to skip a
//!   prompt for the work this program already does, not a remote shell.
//! - The log file a request writes is chosen by the agent, never by the caller,
//!   so a request cannot make an elevated process write to a path of its choosing.

use std::time::Duration;

use anyhow::{Context, Result};

use crate::attach;

/// The words the agent runs. Anything else is refused.
const ALLOWED: [&str; 3] = ["attach", "detach", "dismount"];

/// How long the agent waits for a request before it ends itself.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(600);

/// The pipe the agent listens on: one per user, so two accounts on one machine do
/// not talk to each other's agent.
fn pipe_name() -> String {
    let user: String = std::env::var("USERNAME")
        .unwrap_or_else(|_| "default".to_string())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    format!(r"\\.\pipe\vcrs-agent-{user}")
}

// ------------------------------------------------------------------- the caller

/// The environment variable the agent sets in the children it runs, so a child can
/// tell that an agent is already looking after this machine and must not start
/// another one (which would then ask the first one to do its work, forever).
pub const FROM_AGENT_ENV: &str = "VCRS_FROM_AGENT";

/// Leave an agent behind, unless one is already listening.
///
/// Called from the elevated half of the work — the one run that had a prompt
/// approved. Starting the agent from there costs no second prompt, and the
/// commands after it find it ([`try_run`]) and need none at all. Failing to leave
/// one is not worth an error: the work that was asked for is already done.
pub fn start_if_absent() {
    if std::env::var_os(FROM_AGENT_ENV).is_some() {
        return;
    }
    if exchange("ping").is_some() {
        return;
    }
    let _ = attach::spawn_detached_worker_with(&[
        std::ffi::OsStr::new("agent"),
        std::ffi::OsStr::new("--serve"),
    ]);
}

/// Ask the agent to run these words (the ones `attach`/`detach` would be given).
///
/// `None` when no agent is listening, which is the signal to ask for a prompt the
/// long way. A caller that reached an agent and then lost it gets an error back
/// instead: silently asking for a prompt could mount the volume twice.
pub fn try_run(words: &[String]) -> Option<(i32, String)> {
    let request = format!("run {}", words.join(" "));
    exchange(&request)
}

/// The pid of the running agent, or `None` when there is none.
pub fn status() -> Option<u32> {
    let text = exchange("ping")?.1;
    text.split_whitespace()
        .last()
        .and_then(|word| word.parse().ok())
}

/// Ask the running agent to end itself. `false` when there was none.
pub fn stop() -> bool {
    exchange("stop").is_some()
}

fn exchange(request: &str) -> Option<(i32, String)> {
    let mut pipe = pipe::Pipe::connect(&pipe_name())?;
    let reply = (|| -> Result<String> {
        pipe.write_line(request)?;
        pipe.read_to_end()
    })();
    Some(match reply {
        Ok(text) => split_reply(&text),
        Err(err) => (
            -1,
            format!("vcrs: error: the agent stopped answering: {err:#}\n"),
        ),
    })
}

/// Pull the exit code off the front of a reply (see [`serve`]).
fn split_reply(text: &str) -> (i32, String) {
    let (first, rest) = match text.split_once('\n') {
        Some((first, rest)) => (first, rest),
        None => (text, ""),
    };
    let code = first.trim().parse().unwrap_or(-1);
    (code, rest.to_string())
}

// ------------------------------------------------------------------- the agent

/// Serve requests until the idle timeout passes, or somebody says `stop`.
pub fn serve(idle: Duration) -> Result<()> {
    // The agent outlives the command that started it (it waits for the next one), so a
    // password left in its environment would sit in a long-lived process. Nothing in
    // the agent reads it, and the requests it runs get their secrets over stdin, so
    // it is dropped here — the same reason `vcrs` drops it at startup.
    std::env::remove_var("VCRS_PASSWORD");
    #[cfg(windows)]
    {
        pipe::serve(&pipe_name(), idle)
    }
    #[cfg(not(windows))]
    {
        let _ = idle;
        anyhow::bail!("the agent is a Windows notion; there is none here")
    }
}

/// Run one request: the exit code the work would have had, and what it logged.
fn answer(request: &str) -> (i32, String) {
    match request.trim() {
        "stop" => (0, String::new()),
        "ping" => (0, format!("vcrs agent pid {}\n", std::process::id())),
        line if line.starts_with("run ") => run(line["run ".len()..].trim()),
        other => (
            -1,
            format!("vcrs: error: the agent does not know `{other}`\n"),
        ),
    }
}

/// Run `words` as a console-less `vcrs` child and read back what it logged.
///
/// The child is the same program with `VCRS_ELEVATED_WORKER` set, which is the
/// arrangement `vcrs attach`/`vcrs detach` already use: it does the work and
/// writes its result, `vcrs: done` included, into `--log`.
fn run(words: &str) -> (i32, String) {
    let words: Vec<&str> = words.split_whitespace().collect();
    let Some(first) = words.first() else {
        return (
            -1,
            "vcrs: error: the agent was given no command\n".to_string(),
        );
    };
    if !ALLOWED.contains(first) {
        return (
            -1,
            format!(
                "vcrs: error: the agent only runs `vcrs attach` and `vcrs detach`, not `{first}`\n"
            ),
        );
    }
    match execute(&words) {
        Ok(answer) => answer,
        Err(err) => (-1, format!("vcrs: error: {err:#}\n")),
    }
}

fn execute(words: &[&str]) -> Result<(i32, String)> {
    let exe = std::env::current_exe().context("finding this program's own path")?;
    let log = attach::temp_log_path();
    let _ = std::fs::remove_file(&log);
    let mut command = std::process::Command::new(&exe);
    command
        .args(words)
        .arg("--log")
        .arg(&log)
        .env(attach::WORKER_ENV, "1")
        .env(FROM_AGENT_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // The agent has no console to lend the child, and a console app would
        // allocate one of its own — a window appearing behind the user's back.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let status = command.status().context("running the work")?;
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_file(&log);
    Ok((status.code().unwrap_or(-1), text))
}

/// How long the agent has been quiet, in milliseconds since the epoch.
#[cfg(windows)]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

// -------------------------------------------------------------- the pipe itself

#[cfg(windows)]
mod pipe {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use anyhow::{bail, Result};
    use winapi::shared::sddl::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use winapi::um::fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{TokenUser, GENERIC_READ, GENERIC_WRITE, TOKEN_QUERY, TOKEN_USER};

    use super::{answer, now_ms};

    /// `PIPE_ACCESS_DUPLEX`: both ends may read and write.
    const ACCESS_DUPLEX: u32 = 0x0000_0003;
    /// Byte mode, no message boundaries, blocking — a plain stream.
    const TYPE_BYTE: u32 = 0x0000_0000;
    const READMODE_BYTE: u32 = 0x0000_0000;
    const WAIT: u32 = 0x0000_0000;
    const UNLIMITED_INSTANCES: u32 = 255;
    /// The agent reads a request line; a few kilobytes is generous.
    const BUFFER: usize = 64 * 1024;

    /// The longest request the agent will read off the pipe. The pipe is writable
    /// by anything running as this user, and the reader used to grow a buffer
    /// until it saw a newline — so one caller that never sends one could pin the
    /// memory of the elevated process. A real request is a handful of paths.
    const MAX_REQUEST: usize = 64 * 1024;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// One end of the agent's pipe.
    pub struct Pipe(winapi::shared::ntdef::HANDLE);

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// A handle that closes itself.
    struct Handle(winapi::shared::ntdef::HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    /// A security descriptor and the attributes that hand it to `CreateNamedPipeW`.
    struct Security {
        attributes: SECURITY_ATTRIBUTES,
        descriptor: *mut winapi::ctypes::c_void,
    }

    impl Drop for Security {
        fn drop(&mut self) {
            unsafe { LocalFree(self.descriptor) };
        }
    }

    /// The security the agent's pipe is created with.
    ///
    /// Two things have to be said out loud here. The DACL names this account and
    /// the administrators, so no other account on the machine can ask this agent to
    /// do anything. The mandatory label says *medium* integrity with no write-up:
    /// without it the pipe inherits the agent's own (high) integrity level, and
    /// Windows then refuses the write access a normal, unelevated `vcrs` needs to
    /// send its request — the agent would look dead to the very process it was
    /// started for. (Measured: with the default descriptor, a non-elevated client
    /// could open the pipe for reading and got `Access is denied` for writing.)
    fn pipe_security() -> Result<Security> {
        let sid = current_user_sid()?;
        let sddl = wide(&format!(
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})S:(ML;;NW;;;ME)"
        ));
        let mut descriptor: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1 as u32,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            bail!("could not build the agent pipe's security descriptor");
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Security {
            attributes,
            descriptor,
        })
    }

    /// The SID of the account this process runs as, as SDDL text.
    fn current_user_sid() -> Result<String> {
        let mut token: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            bail!("could not open this process' own token");
        }
        let _close = Handle(token);
        // Ask for the size first, then read the user out of a buffer of that size.
        let mut needed: u32 = 0;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u8; needed.max(64) as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            bail!("could not read this process' user");
        }
        let user: *const TOKEN_USER = buffer.as_ptr().cast();
        let mut text: *mut u16 = std::ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW((*user).User.Sid, &mut text) };
        if ok == 0 {
            bail!("could not name this process' user");
        }
        let sid = from_wide(text);
        unsafe { LocalFree(text.cast()) };
        Ok(sid)
    }

    /// A NUL-terminated UTF-16 string from the operating system.
    fn from_wide(pointer: *const u16) -> String {
        let mut length = 0usize;
        while unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        let text = unsafe { std::slice::from_raw_parts(pointer, length) };
        String::from_utf16_lossy(text)
    }

    impl Pipe {
        /// Connect to the agent, or `None` when there is none (the pipe is missing).
        pub fn connect(name: &str) -> Option<Pipe> {
            let path = wide(name);
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return None;
            }
            Some(Pipe(handle))
        }

        pub fn write_line(&mut self, line: &str) -> Result<()> {
            let text = format!("{line}\n");
            write_all(self.0, text.as_bytes())
        }

        /// Read until the agent closes its end, which is how a reply ends.
        pub fn read_to_end(&mut self) -> Result<String> {
            let mut bytes = Vec::new();
            let mut buffer = vec![0u8; 4096];
            loop {
                let mut read: u32 = 0;
                let ok = unsafe {
                    ReadFile(
                        self.0,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 || read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read as usize]);
            }
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    fn write_all(handle: winapi::shared::ntdef::HANDLE, bytes: &[u8]) -> Result<()> {
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            bail!("writing to the agent pipe failed");
        }
        Ok(())
    }

    /// Listen until the idle timeout passes with no request, or somebody says `stop`.
    pub fn serve(name: &str, idle: Duration) -> Result<()> {
        let path = wide(name);
        let security = pipe_security()?;
        let pipe = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                ACCESS_DUPLEX,
                TYPE_BYTE | READMODE_BYTE | WAIT,
                UNLIMITED_INSTANCES,
                BUFFER as u32,
                BUFFER as u32,
                0,
                &security.attributes as *const _ as *mut _,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            bail!("could not open the agent pipe {name}");
        }
        let _close = Pipe(pipe);
        // Whoever is watching for idleness starts from "just now".
        let last = Arc::new(AtomicU64::new(now_ms()));
        watch_for_idleness(idle, Arc::clone(&last));
        loop {
            // Nothing to do but wait for a caller. A caller that connected while we
            // were away already satisfies this call.
            unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
            let request = read_line(pipe).unwrap_or_default();
            last.store(now_ms(), Ordering::Relaxed);
            let (code, text) = answer(&request);
            let _ = write_all(pipe, format!("{code}\n{text}").as_bytes());
            unsafe {
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
            }
            if request.trim() == "stop" {
                return Ok(());
            }
        }
    }

    fn read_line(handle: winapi::shared::ntdef::HANDLE) -> Result<String> {
        let mut bytes = Vec::new();
        let mut buffer = vec![0u8; 4096];
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.contains(&b'\n') {
                break;
            }
            if bytes.len() > MAX_REQUEST {
                anyhow::bail!(
                    "the request on the agent pipe is over {MAX_REQUEST} bytes and has no newline; \
                     refusing it"
                );
            }
        }
        Ok(String::from_utf8_lossy(&bytes).trim().to_string())
    }

    /// End the agent when nobody has asked it anything for a while.
    ///
    /// The server is parked in `ConnectNamedPipe`, so the watchdog has to knock:
    /// it connects and asks for `stop`, which the server handles like any other
    /// request. A real caller arriving first simply resets the clock.
    fn watch_for_idleness(idle: Duration, last: Arc<AtomicU64>) {
        std::thread::spawn(move || {
            let started = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let quiet_for =
                    Duration::from_millis(now_ms().saturating_sub(last.load(Ordering::Relaxed)));
                if quiet_for >= idle {
                    let _ = super::exchange("stop");
                    return;
                }
                // A clock that jumps backwards (or a very long `idle`) must not keep
                // the thread alive forever when the agent has been replaced.
                if started.elapsed() > idle + Duration::from_secs(3600) {
                    return;
                }
            }
        });
    }
}
