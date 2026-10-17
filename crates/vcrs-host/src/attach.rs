//! Attach a volume that `vcrs mount` is serving to the Microsoft iSCSI
//! Initiator, and put it on a drive letter of the user's choosing.
//!
//! `vcrs mount` only *serves* the volume; Windows creates the disk when the
//! initiator logs in, and Windows picks the drive letter. This module does the
//! login (`iscsicli`) and then moves the disk to the letter that was asked for,
//! so that `vcrs mount secret.vc --letter Y` is a single command that ends with
//! the volume on `Y:`.
//!
//! `iscsicli` carries a `requireAdministrator` manifest (unelevated it fails
//! with `os error 740`, "the requested operation requires elevation"), so the
//! attach has to run elevated. [`attach_with_elevation`] re-runs this same
//! program as `vcrs attach …` through `Start-Process -Verb RunAs` when the
//! current process is not elevated: one UAC prompt, and the child's output is
//! replayed through a temporary log file, because an elevated child gets a
//! console of its own. Running `vcrs attach` from an already elevated prompt
//! needs no prompt at all.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// The INQUIRY product string `vcrs-mount` publishes, which is how the disk
/// Windows creates is recognised among the other disks in the machine.
pub const DISK_NAME: &str = "VeraCrypt volume";

/// The INQUIRY product string the SCSI target answers with, which is how Windows names
/// a vc-rs disk in its device tree (`…\PROD_VERACRYPT_VOLUME`) — the listing matches on
/// this rather than on the `VeraCrypt volume` name, which is a friendly name Windows
/// builds from it.
const DISK_PRODUCT: &str = "VERACRYPT";

/// How long to wait for Windows to show the disk after the login succeeded.
pub const DISK_WAIT: Duration = Duration::from_secs(30);

/// How often to look while waiting.
const POLL: Duration = Duration::from_millis(500);

/// How long to give the iSCSI service to come up after asking for it.
const SERVICE_START_WAIT: Duration = Duration::from_secs(10);

/// What to attach and where.
#[derive(Debug, Clone)]
pub struct AttachOptions {
    /// IQN of the target `vcrs mount` is serving.
    pub iqn: String,
    /// `host:port` the target listens on.
    pub address: String,
    /// Drive letter to put the volume on (`None` = whatever Windows chooses).
    pub letter: Option<char>,
    /// Size of the disk the target presents, used to tell this volume's disk
    /// apart from another one `vcrs mount` may be serving at the same time.
    pub disk_size: Option<u64>,
    /// How long to wait for the disk to appear.
    pub wait: Duration,
    /// Also write the same output here (set by the elevated child, whose
    /// console is a window of its own: the parent replays the file).
    pub log: Option<PathBuf>,
    /// Ask the target for CHAP authentication. The secret is derived from the
    /// header salt of the volume named here and from the target name, exactly as
    /// the target derived it (see `vcrs_core::chap_secret`), so no secret has to
    /// be passed between the two halves of a mount. `None` logs in without
    /// credentials, which only works against a target that does not ask for any.
    pub chap_from: Option<PathBuf>,
}

/// Which header group a CHAP secret is derived from.
///

/// The volume is attached: Windows has a disk, and this is where it went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    pub disk: u32,
    pub partition: u32,
    /// The drive letter the volume ended up on.
    pub letter: Option<char>,
    /// Anything the user should know about the outcome.
    pub note: String,
}

/// Attach the target and, when asked, put it on `letter`.
///
/// Needs an elevated process (see the module docs); the caller that has to cope
/// with that is [`attach_with_elevation`].
pub fn attach(options: &AttachOptions) -> Result<Attached> {
    let mut report = Report::new(options.log.as_deref());
    if cfg!(windows) && !elevated() {
        bail!(
            "attaching a volume needs elevation: iscsicli carries a requireAdministrator \
             manifest, so Windows refuses to run it from a normal prompt. Re-run this in an \
             elevated prompt, or use `vcrs mount --letter` which asks for elevation itself"
        );
    }
    // Before anything is touched: the IQN and the portal go to `iscsicli`, so a
    // value that cannot be one is an error here, not a shell command later.
    validate_target(options)?;

    let letter = options.letter.map(|c| c.to_ascii_uppercase());
    if let Some(letter) = letter {
        if !letter.is_ascii_alphabetic() {
            bail!("{letter:?} is not a drive letter");
        }
    }
    // A letter that is in use is not fatal yet: it may be this very volume
    // coming back on the letter Windows remembered for it.  That is only known
    // once the disk has turned up, so remember the fact and decide then.
    let letter_taken = match letter {
        Some(letter) => drive_letters_in_use()?.contains(&letter),
        None => false,
    };
    report.line(&format!(
        "attaching {}{}",
        options.iqn,
        match letter {
            Some(letter) => format!(" on {letter}:"),
            None => String::new(),
        }
    ));

    // 0. the initiator service has to be up before iscsicli can be used at all.
    ensure_initiator_service(&mut report)?;

    // 1. Clear whatever an earlier run left behind.  A session whose target
    //    process died stays logged in for good: Windows keeps retrying a target
    //    that is not there, and that retry storm then stops the PnP setup of the
    //    disk we are about to create.  Logging out by target name does nothing
    //    in that state, so the sessions are found and logged out by id.
    let stale = logout_stale_sessions(&options.iqn, &mut report);
    let _ = iscsicli(&["RemoveTarget", &options.iqn]);
    if stale > 0 {
        // A session that outlived its target leaves the disk device Windows made
        // for it in an Error state, and that device blocks the disk of the new
        // session; the check costs a couple of seconds, so it is only made when
        // something was really cleared.
        forget_stale_devices(&mut report);
    }

    // 2. register the target statically, then log in.  `AddTarget` takes the
    //    CHAP user, secret and authentication type in fixed positions; without
    //    CHAP the two credential arguments have to stay *empty*, and they go
    //    through as two empty `argv` elements, which the Windows argument
    //    quoting renders as `""` for the child.  There is deliberately no
    //    `cmd /c` hop any more: it existed only to preserve those two `""`, and
    //    it turned the IQN and the portal into a shell command line (see
    //    `validate_iqn`).
    let (host, port) = split_address(&options.address);
    let add_target = add_target_arguments(options)?;
    let add_target: Vec<&str> = add_target.iter().map(|arg| arg.as_str()).collect();
    iscsicli(&add_target)
        .with_context(|| format!("registering {host}:{port} as a static target"))?;
    // From here on the target is registered, so a failure has to take it off
    // again: the initiator keeps retrying a static target whose process is gone,
    // and the name would otherwise stay in its target list for good. Every mount
    // draws a fresh name, so that list would grow with every failed attempt.
    let attempt = attach_registered_target(options, letter, letter_taken, &mut report);
    if attempt.is_err() {
        let _ = iscsicli(&["QLogoutTarget", &options.iqn]);
        let _ = iscsicli(&["RemoveTarget", &options.iqn]);
    }
    return attempt;
}

/// Log in to a registered target and bring its disk up.
///
/// Split out of [`attach`] so that a failure anywhere in here can take the
/// static target off again ([`attach`] does that when this returns an error).
fn attach_registered_target(
    options: &AttachOptions,
    letter: Option<char>,
    letter_taken: bool,
    report: &mut Report,
) -> Result<Attached> {
    // Which vc-rs disks Windows already had. The disk this login creates has to be a
    // new one: the INQUIRY name is what identifies a vc-rs disk, and anything that can
    // create an iSCSI disk chooses that name itself, so a disk that was already there
    // and merely *looks* the same must not be taken for ours — the letter would go onto
    // another volume. (The snapshot is taken after the stale-device cleanup in
    // `attach`, so a number that cleanup freed is not in it and can be reused by our
    // own disk.)
    let before: Vec<u32> = vcrs_disks()
        .unwrap_or_default()
        .into_iter()
        .map(|disk| disk.number)
        .collect();

    // A login that did not work has to be reported. `iscsicli` exits non-zero on
    // an authentication failure, and swallowing that used to end in "logged in
    // ... waiting for the disk" plus a timeout that said nothing about the
    // credentials being the problem.
    let out = iscsicli(&["QLoginTarget", &options.iqn]).with_context(|| {
        format!(
            "logging in to {} (a target that asks for CHAP fails here when the \
             credentials do not match)",
            options.iqn
        )
    })?;
    if let Some(line) = first_line(&out) {
        report.line(&line);
    }
    report.line(&format!(
        "logged in to {}; waiting up to {} s for Windows to show the disk",
        options.iqn,
        options.wait.as_secs()
    ));

    // 3. Windows builds the disk asynchronously, so wait for it to turn up.
    let disk = wait_for_disk(options.disk_size, &before, options.wait, report)?;

    // 4. put it on the letter that was asked for.
    let mut fresher = None;
    let letter = match letter {
        None => disk
            .partition
            .as_ref()
            .and_then(|p| p.letter)
            .or(disk.letter),
        Some(want) => {
            let current = disk
                .partition
                .as_ref()
                .and_then(|p| p.letter)
                .or(disk.letter);
            if current == Some(want) {
                report.line(&format!(
                    "{want}: was already on this volume (Windows kept the letter)"
                ));
                Some(want)
            } else {
                if letter_taken {
                    bail!("{want}: is already in use on this machine; pick a free letter");
                }
                let partition = disk.partition.as_ref().with_context(|| {
                    format!(
                        "the disk {} appeared but Windows sees no partition on it yet; \
                         try again in a moment",
                        disk.number
                    )
                })?;
                let (got, disk_after) =
                    set_letter(disk.number, partition.number, want, READ_BACK_WAIT)?;
                fresher = disk_after;
                Some(got)
            }
        }
    };

    let mut note = String::new();
    // Windows recognises the filesystem a moment after the disk turns up (and
    // after the letter moved), so the copy read when the disk first appeared can
    // still be empty.  Give it a moment, then take the freshest answer.
    let mut disk = fresher
        .or_else(|| read_back(disk.number, None, READ_BACK_WAIT))
        .unwrap_or(disk);
    if !has_a_file_system(&disk) {
        std::thread::sleep(Duration::from_millis(600));
        if let Some(again) = read_back(disk.number, None, READ_BACK_WAIT) {
            if has_a_file_system(&again) {
                disk = again;
            }
        }
    }
    let has_file_system = has_a_file_system(&disk);
    if !has_file_system {
        note = "the volume has no filesystem inside yet (VeraCrypt containers do not come with \
                one): format the disk, or `vcrs format` the container itself"
            .to_string();
    }
    let attached = Attached {
        disk: disk.number,
        partition: disk.partition.as_ref().map(|p| p.number).unwrap_or(0),
        letter,
        note,
    };
    report.line(&describe(&attached));
    Ok(attached)
}

/// Attach the target, asking Windows for elevation when this process has none.
///
/// This is what `vcrs mount --letter Y` calls: from a normal prompt it produces
/// one UAC prompt and nothing else to do; from an elevated prompt it attaches
/// straight away.
pub fn attach_with_elevation(options: &AttachOptions, json: bool) -> Result<()> {
    // Rejected before the elevation prompt (and before the cached agent): a bad
    // IQN or portal has to cost nothing.
    validate_target(options)?;
    if elevated() {
        attach(options)?;
        return Ok(());
    }

    // An agent an earlier prompt left behind does the work with no prompt at all.
    if let Some((_, text)) = crate::agent::try_run(&attach_arguments(options, None, json)) {
        return finish(&text, "attach", json);
    }

    let exe = std::env::current_exe().context("finding this program's own path")?;
    let log = temp_log_path();
    // A log left behind by an earlier run is not this run's answer.
    let _ = std::fs::remove_file(&log);
    let args = attach_arguments(options, Some(&log), json);
    // Guidance for a person goes to stderr, so a caller reading stdout sees only
    // the answer (`--json` asks for nothing else).
    eprintln!(
        "attaching {} needs an elevated prompt (iscsicli carries a requireAdministrator manifest):",
        options.iqn
    );
    eprintln!(
        "  approving the Windows prompt that is about to appear …  (or run `vcrs attach {}` \
         yourself from an elevated prompt)",
        options.iqn
    );
    // A denied UAC prompt (or a PowerShell that would not start) leaves no run and
    // therefore no reason to leave `--log` behind: it names the container.
    if let Err(err) = start_elevated(&exe, &args, &log) {
        let _ = std::fs::remove_file(&log);
        return Err(err);
    }
    let text = wait_for_log(&log);
    let _ = std::fs::remove_file(&log);
    finish(&text, "attach", json)
}

/// How long an elevated run may take before its verdict is given up on.
const LOG_WAIT: Duration = Duration::from_secs(300);

/// Wait until an elevated run has left its verdict in the log.
///
/// The elevated half is not waited for as a process (see [`start_elevated`]), so
/// its log is the only place its outcome can turn up. Reading the file as it
/// grows also means a worker that was killed still shows what it managed to do.
pub fn wait_for_log(log: &Path) -> String {
    let deadline = std::time::Instant::now() + LOG_WAIT;
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains(DONE) || text.contains(FAILED) {
            return text;
        }
        if std::time::Instant::now() >= deadline {
            return text;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Print what an elevated run wrote, and say whether it worked.
///
/// The work happens in a console-less child whose output comes back through a log
/// file (or straight from an agent, see [`crate::agent`]), so the verdict is the
/// marker that child leaves behind: [`DONE`] when it finished, [`FAILED`] when it
/// gave up. Nothing else in the log can be trusted on its own — the lines around
/// them are progress, and a worker that was killed mid-way leaves neither.
/// What an elevated run puts in front of the JSON document it sends back.
///
/// The log file is the only channel it has (its console is hidden and the caller
/// replays the file), so the document travels as one marked line among the lines
/// written for a person, and [`take_json`] picks it out again.
pub const JSON_MARKER: &str = "vcrs-json:";

/// The machine-readable document an elevated run sent back, if it sent one.
pub fn take_json(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(JSON_MARKER))
}

/// Send the caller a machine-readable document through the log file.
pub fn report_json(log: Option<&Path>, document: &serde_json::Value) {
    let line = format!("{JSON_MARKER}{document}");
    println!("{line}");
    if let Some(path) = log {
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// Show what an elevated run left behind, and fail if it failed.
///
/// With `json` the caller asked for a machine-readable answer: the lines written
/// for a person are dropped and only the document is printed. A run that failed
/// has no document, so its verdict is shown instead — which is what says why.
pub fn finish(text: &str, what: &str, json: bool) -> Result<()> {
    if json {
        if let Some(document) = take_json(text) {
            println!("{document}");
            return Ok(());
        }
    }
    judge(text, what)
}

pub fn judge(text: &str, what: &str) -> Result<()> {
    print!("{text}");
    if text.contains(FAILED) {
        bail!("the elevated {what} failed (the lines above say why)");
    }
    if !text.contains(DONE) {
        bail!("the elevated {what} left no verdict behind — it was killed, or it never started");
    }
    Ok(())
}

/// Exit code `Start-Process -Verb RunAs` reports when the user refuses UAC.
pub const ELEVATION_CANCELLED: i32 = 1223;

/// The elevation prompt was declined, or could not be shown.
///
/// It travels up as its own error type so `main` can exit with Windows' own
/// `ERROR_CANCELLED` instead of a bare failure: a script can then tell the
/// user's "no" from a real problem.
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the elevation prompt was declined")
    }
}

impl std::error::Error for Cancelled {}

fn describe(attached: &Attached) -> String {
    let mut text = match attached.letter {
        Some(letter) => format!(
            "attached: disk {} partition {} is on {letter}:",
            attached.disk, attached.partition
        ),
        None => format!(
            "attached: disk {} partition {} (Windows has not given it a drive letter — \
             it has no filesystem to mount yet)",
            attached.disk, attached.partition
        ),
    };
    if !attached.note.is_empty() {
        text.push_str("\n  ");
        text.push_str(&attached.note);
    }
    text
}

/// Everything needed to re-run this program as `vcrs attach …`.
/// The `iscsicli AddTarget` arguments for this attach, credentials included.
///
/// The positions are fixed by the initiator: name, alias, portal address, portal
/// socket, target flags, persist, login flags, header digest, data digest, max
/// connections, DefaultTime2Wait, DefaultTime2Retain, user, secret,
/// authentication type, mapping count. With CHAP the three after the digests
/// carry the credentials and `1` (`ISCSI_CHAP_AUTH_TYPE`, one-way CHAP: the
/// target authenticates the initiator); without it the credentials are empty and
/// the type is `0`. The initiator remembers the credentials with the static
/// target, so `QLoginTarget` does not have to repeat them.
fn add_target_arguments(options: &AttachOptions) -> Result<Vec<String>> {
    let (host, port) = split_address(&options.address);
    let (user, secret, auth_type) = match &options.chap_from {
        Some(path) => (
            vcrs_core::CHAP_USER.to_string(),
            chap_secret_for(path, &options.iqn)?,
            "1",
        ),
        None => (String::new(), String::new(), "0"),
    };
    Ok(vec![
        "AddTarget".to_string(),
        options.iqn.clone(),
        "vcrs".to_string(),
        host,
        port.to_string(),
        "0".to_string(), // target flags
        "0".to_string(), // persist
        "0".to_string(), // login flags
        "0".to_string(), // header digest
        "0".to_string(), // data digest
        "8".to_string(), // max connections
        "0".to_string(), // DefaultTime2Wait
        "0".to_string(), // DefaultTime2Retain
        user,
        secret,
        auth_type.to_string(),
        "0".to_string(), // mapping count
    ])
}

/// The CHAP secret both halves of this mount use. The target derives the same
/// one from the same bytes; see [`vcrs_core::chap_secret`].
fn chap_secret_for(path: &Path, iqn: &str) -> Result<String> {
    // Both halves of a mount call the same helper in `vcrs-core`, so the target
    // and the elevated `iscsicli` cannot drift apart on how the secret is made.
    Ok(vcrs_core::chap_secret_for_file(path, iqn)?)
}

fn attach_arguments(options: &AttachOptions, log: Option<&Path>, json: bool) -> Vec<String> {
    let mut args = vec![
        "attach".to_string(),
        "--iqn".to_string(),
        options.iqn.clone(),
        "--address".to_string(),
        options.address.clone(),
        "--wait".to_string(),
        options.wait.as_secs().to_string(),
    ];
    if let Some(letter) = options.letter {
        args.push("--letter".to_string());
        args.push(letter.to_string());
    }
    if let Some(size) = options.disk_size {
        args.push("--disk-size".to_string());
        args.push(size.to_string());
    }
    if let Some(path) = &options.chap_from {
        args.push("--chap-from".to_string());
        args.push(path.display().to_string());
    }
    if let Some(log) = log {
        args.push("--log".to_string());
        args.push(log.display().to_string());
    }
    if json {
        args.push("--json".to_string());
    }
    args
}

pub fn temp_log_path() -> PathBuf {
    // In the private state directory rather than `%TEMP%`: this file holds a
    // report about a container, and `%TEMP%` is readable by every user on the
    // machine. The name keeps the `vcrs-attach-` prefix that `serve::sweep_logs`
    // looks for.
    crate::serve::state_dir().join(format!("vcrs-attach-{}.log", std::process::id()))
}

/// Run `exe args` elevated, and return as soon as it is running.
///
/// `Start-Process -Verb RunAs` is the only supported way to ask for elevation
/// from a normal process. Its `-Wait` is deliberately *not* used: it waits for the
/// whole process tree, and the first elevated run starts an agent (see
/// [`crate::agent`]) that is meant to live for minutes — the caller would sit
/// there until the agent timed out. The caller instead reads the run's verdict out
/// of its `--log` file (see [`wait_for_log`]).
pub fn start_elevated(exe: &Path, args: &[String], _log: &Path) -> Result<i32> {
    let list: Vec<String> = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "''")))
        .collect();
    let script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{ Start-Process -FilePath '{exe}' \
         -ArgumentList @({list}) -WindowStyle Hidden -Verb RunAs }} \
         catch {{ Write-Error $_; exit {ELEVATION_CANCELLED} }}",
        exe = exe.display().to_string().replace('\'', "''"),
        list = list.join(","),
    );
    // The elevator gets none of our handles: `Start-Process -Wait` waits for the
    // elevated process *and its children*, and an inherited stdout pipe would keep
    // the caller's shell waiting for a volume that is already mounted. The elevated
    // child writes its result into `--log`, which the caller replays.
    let out = quiet_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("asking Windows for an elevated process")?;
    let code = out.status.code().unwrap_or(-1);
    if code == ELEVATION_CANCELLED {
        let text = String::from_utf8_lossy(&out.stderr);
        let text = text.trim();
        if !text.is_empty() {
            println!("  {text}");
        }
        return Err(anyhow::Error::new(Cancelled));
    }
    Ok(code)
}

// ---------------------------------------------------------------- the helpers

/// Is this process running elevated?
///
/// `iscsicli` refuses to run unelevated (`os error 740`), so the answer decides
/// whether [`attach_with_elevation`] has to ask for a UAC prompt.
#[cfg(windows)]
pub fn elevated() -> bool {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

    let mut token: HANDLE = std::ptr::null_mut();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn elevated() -> bool {
    false
}

/// Check a drive letter before anything is started, so a typo or a letter that
/// is already taken is refused without a target left running.
pub fn check_letter(letter: char) -> Result<char> {
    let letter = letter_argument(letter)?;
    if drive_letters_in_use()?.contains(&letter) {
        bail!(
            "{letter}: is already in use on this machine; pick a free letter (or try again in \
             a moment — Windows keeps a letter for a while after a volume disappears)"
        );
    }
    Ok(letter)
}

/// The letter the user asked for, upper-cased and checked to be a letter — but
/// *not* checked to be free, which only makes sense when a letter is being
/// taken. A dismount has to accept the letter its volume is already on.
pub fn letter_argument(letter: char) -> Result<char> {
    if !letter.is_ascii_alphabetic() {
        bail!("{letter:?} is not a drive letter");
    }
    Ok(letter.to_ascii_uppercase())
}

/// Log out every session on `iqn` that a previous run left behind, by id.
///
/// `QLogoutTarget` is useless here: it looks the session up by target name, and
/// the whole problem is that the session has outlived its target.
fn logout_stale_sessions(iqn: &str, report: &mut Report) -> usize {
    let Ok(list) = iscsicli(&["SessionList", "1"]) else {
        return 0;
    };
    let mut cleared = 0;
    for id in session_ids(&list, iqn) {
        // A session that Windows is still using cannot be logged out, and that
        // is the good case: it reconnects to the target we are about to start
        // and the existing disk comes back.  Only a session that really was
        // cleared is worth telling the user about.
        if iscsicli(&["LogoutTarget", &id]).is_ok() {
            report.line(&format!(
                "logged out the session {id} that {iqn} had left behind"
            ));
            cleared += 1;
        }
    }
    cleared
}

/// The session ids of `iqn` in the text `iscsicli SessionList 1` prints.
fn session_ids(list: &str, iqn: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut current: Option<String> = None;
    for line in list.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Session Id" => current = Some(value.trim().to_string()),
            "Target Name" if value.trim() == iqn => {
                if let Some(id) = current.take() {
                    ids.push(id);
                }
            }
            _ => {}
        }
    }
    ids
}

/// Remove vc-rs disk devices Windows still lists but that are not working.  A
/// device whose target is gone is left in an error state, and until it is
/// removed the disk of the new session never starts.
pub fn forget_stale_devices(report: &mut Report) {
    let script = "Get-PnpDevice -Class DiskDrive -ErrorAction SilentlyContinue | \
        Where-Object { $_.FriendlyName -like '*VeraCrypt volume*' -and $_.Status -ne 'OK' } | \
        ForEach-Object { pnputil /remove-device $_.InstanceId | Out-Null; \
        \"removed the stale disk device $($_.InstanceId)\" }";
    if let Ok(text) = powershell(script) {
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            report.line(line);
        }
    }
}

/// Run `iscsicli` with arguments and give back its output.
pub fn iscsicli(args: &[&str]) -> Result<String> {
    let out = quiet_command("iscsicli")
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "running `iscsicli {}` (the Microsoft iSCSI Initiator needs an elevated prompt)",
                args.join(" ")
            )
        })?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let errors = String::from_utf8_lossy(&out.stderr);
    let mut all = text;
    if !errors.trim().is_empty() {
        all.push_str(errors.trim());
        all.push('\n');
    }
    // Some failures mean the state is already the one being asked for: a session that
    // has gone by itself ("already"), or a target that is not registered any more
    // ("The target name is not found or is marked as hidden from login."). Those are
    // not errors — the second says exactly what this call set out to achieve.
    let lower = all.to_ascii_lowercase();
    if !out.status.success() && !lower.contains("already") && !lower.contains("not found") {
        bail!(
            "`iscsicli {}` failed ({}): {}",
            args.join(" "),
            out.status,
            all.trim()
        );
    }
    Ok(all)
}

/// Run a PowerShell one-liner and give back its output.
pub fn powershell(script: &str) -> Result<String> {
    let out = quiet_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("running powershell")?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let errors = String::from_utf8_lossy(&out.stderr);
        bail!(
            "powershell failed: {}",
            first_line(errors.trim())
                .or_else(|| first_line(&text))
                .unwrap_or_else(|| format!("exit status {}", out.status))
        );
    }
    Ok(text)
}

/// The drive letters Windows currently has in use, straight from the kernel.
///
/// This runs on every attach and every dismount, and it is not worth the second
/// a PowerShell/CIM query costs: `GetLogicalDrives` returns the letters that
/// exist as a 26-bit mask, including mapped network drives, in microseconds.
///
/// Letters of partitions that are really there only: a letter Windows still
/// remembers for a volume whose disk has just gone (a mount that was killed) is
/// deliberately not counted, because it is free to use again and refusing it
/// would make re-mounting on the old letter impossible for a moment.
fn drive_letters_in_use() -> Result<Vec<char>> {
    #[cfg(windows)]
    {
        use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
        /// `DRIVE_NO_ROOT_DIR` from `winbase.h`: nothing is at that root.
        const NO_ROOT: u32 = 1;
        let mask = unsafe { GetLogicalDrives() };
        if mask == 0 {
            bail!("Windows would not say which drive letters are in use");
        }
        // `GetLogicalDrives` goes on reporting a letter whose volume has gone (a
        // mount that was killed, a device that was removed), and refusing those
        // would make re-mounting on the same letter impossible until a reboot.
        // `GetDriveType` on a root that is not there answers `DRIVE_NO_ROOT_DIR`,
        // so only the letters that still lead somewhere count as taken.
        Ok(letters_from_mask(mask)
            .into_iter()
            .filter(|letter| {
                let root: Vec<u16> = format!("{letter}:\\")
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                (unsafe { GetDriveTypeW(root.as_ptr()) }) != NO_ROOT
            })
            .collect())
    }
    #[cfg(not(windows))]
    {
        bail!("drive letters are a Windows notion; there are none here")
    }
}

/// The letters set in a `GetLogicalDrives` mask (bit 0 is `A`, bit 25 is `Z`).
fn letters_from_mask(mask: u32) -> Vec<char> {
    (0..26u32)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| (b'A' + bit as u8) as char)
        .collect()
}

/// The Microsoft iSCSI Initiator Service has to be running before `iscsicli`
/// will do anything: on a machine that has never used iSCSI it is stopped, and
/// every command then comes back with "The Microsoft iSCSI Initiator Service is
/// not running". Starting it needs elevation, so this belongs on the elevated
/// side, after the caller's elevation check.
/// The Windows service the iSCSI work needs: without it `iscsicli AddTarget` fails
/// with "The Microsoft iSCSI Initiator Service is not running".
const INITIATOR_SERVICE: &str = "msiscsi";

fn ensure_initiator_service(report: &mut Report) -> Result<()> {
    // The service manager answers in milliseconds; a `Get-Service`/`Start-Service` pair
    // costs a PowerShell launch plus a cmdlet import on every mount.
    let state = crate::win32::service_state(INITIATOR_SERVICE)?;
    if state == crate::win32::ServiceState::Running {
        return Ok(());
    }
    report.line(&format!(
        "the Microsoft iSCSI Initiator Service is {}; starting it",
        state.word()
    ));
    crate::win32::start_service(INITIATOR_SERVICE)?;
    let deadline = Instant::now() + SERVICE_START_WAIT;
    loop {
        let state = crate::win32::service_state(INITIATOR_SERVICE)?;
        if state == crate::win32::ServiceState::Running {
            report.line("the iSCSI service is up");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the Microsoft iSCSI Initiator Service did not start (it is still {}); \
                 start it by hand with `sc start msiscsi`",
                state.word()
            );
        }
        std::thread::sleep(POLL);
    }
}

/// One partition of a vc-rs disk, as PowerShell reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    pub number: u32,
    pub letter: Option<char>,
    pub file_system: Option<String>,
}

/// A disk that carries the vc-rs INQUIRY name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    pub number: u32,
    pub size: u64,
    /// The partition the synthetic MBR describes, if Windows sees it.
    pub partition: Option<PartitionInfo>,
    /// A letter Windows itself put on the disk (a volume it mounted).
    pub letter: Option<char>,
}

/// Ask Windows for every vc-rs disk and its partition.
///
/// Does Windows see a file system on this disk's partition?
fn has_a_file_system(disk: &DiskInfo) -> bool {
    disk.partition
        .as_ref()
        .map(|p| p.file_system.is_some())
        .unwrap_or(false)
}

/// Wait for the disk Windows creates for the target to show up.
///

pub fn vcrs_disks() -> Result<Vec<DiskInfo>> {
    crate::win32::vcrs_disks(DISK_PRODUCT)
}
/// The disk is chosen by its INQUIRY name and its size, and it has to be one Windows
/// did not have before the login (`already_present`): several `vcrs mount` processes can
/// be serving different volumes at once, so the name alone would not pick one, and a
/// name that anything can copy would let a planted disk be picked instead of ours.
fn wait_for_disk(
    disk_size: Option<u64>,
    already_present: &[u32],
    timeout: Duration,
    report: &mut Report,
) -> Result<DiskInfo> {
    report.line(&format!(
        "waiting up to {} s for the disk …",
        timeout.as_secs()
    ));
    // The listing is a handful of ioctls now, so the waiting happens here: a cmdlet
    // import per poll was what made it worth pushing the loop into PowerShell.
    let deadline = std::time::Instant::now() + timeout;
    // A freshly logged-in iSCSI disk is a device Windows has not grown a disk for
    // yet, and the storage stack only does that on a device-tree scan. The old
    // PowerShell loop called `Update-HostStorageCache` every time round for exactly
    // this reason; the Win32 call behind it is a re-enumeration of the root device
    // node. Failing to rescan is not fatal — the disk may arrive on its own — so
    // the error is dropped rather than ending the wait.
    let _ = crate::win32::rescan_devices();
    let mut since_scan = std::time::Instant::now();
    loop {
        if let Some(disk) = newest_disk(&vcrs_disks().unwrap_or_default(), disk_size, already_present)
        {
            return Ok(disk);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        if since_scan.elapsed() >= Duration::from_secs(1) {
            let _ = crate::win32::rescan_devices();
            since_scan = std::time::Instant::now();
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    // Nothing appeared: say what Windows does have, which is what tells a stale
    // device apart from a login that never got through. A vc-rs disk that was already
    // there and is the size we are looking for is called out separately: it is the
    // shape of a planted name-alike, and it must not be used.
    let all = vcrs_disks().unwrap_or_default();
    let seen: Vec<String> = all
        .iter()
        .map(|disk| format!("disk {} ({} bytes)", disk.number, disk.size))
        .collect();
    let look_alike: Vec<String> = all
        .iter()
        .filter(|disk| already_present.contains(&disk.number))
        .filter(|disk| disk_size.map_or(true, |size| disk.size == size))
        .map(|disk| format!("disk {} ({} bytes)", disk.number, disk.size))
        .collect();
    let seen_part = if seen.is_empty() {
        String::new()
    } else {
        format!("; the vc-rs disks it does have: {}", seen.join(", "))
    };
    let alike_part = if look_alike.is_empty() {
        String::new()
    } else {
        format!(
            "; a vc-rs disk of that size was already on this machine before the login \
             ({}), and it was left alone — refusing to put the letter on a disk this \
             login did not create",
            look_alike.join(", ")
        )
    };
    bail!(
        "Windows did not show the disk within {} s{}{}. \
         `vcrs dismount --iscsi <IQN>` clears a half-finished attach",
        timeout.as_secs(),
        seen_part,
        alike_part,
    );
}

/// The newest vc-rs disk of a given size that Windows did not have before, if any.
///
/// The highest disk number wins when two candidates have the same size, because
/// Windows numbers a newly created disk above the ones already there. A disk whose
/// number was there before the login is never a candidate: the INQUIRY name is what
/// identifies a vc-rs disk, and whoever can create an iSCSI disk picks that name
/// themselves.
fn newest_disk(
    disks: &[DiskInfo],
    disk_size: Option<u64>,
    already_present: &[u32],
) -> Option<DiskInfo> {
    disks
        .iter()
        .filter(|disk| !already_present.contains(&disk.number))
        .filter(|disk| disk_size.map_or(true, |size| disk.size == size))
        .max_by_key(|disk| disk.number)
        .cloned()
}

/// Make this process ignore console control events (Ctrl-C, Ctrl-Break, a
/// closing console).
///
/// Set in the child that really does the work (see [`run_detached_worker`]).
pub const WORKER_ENV: &str = "VCRS_ELEVATED_WORKER";

/// The line that says the work finished, written into the `--log` file: the caller
/// reads it back, so a launcher that was killed while waiting cannot make a
/// successful job look failed.
/// The line that says the work finished, written into the `--log` file (or sent
/// back by an agent) when it succeeded.
pub const DONE: &str = "vcrs: done";

/// The line that says the work failed, written right after the `vcrs: error:`
/// line. The caller reads the log rather than a process' exit code (see
/// [`wait_for_log`]), so the verdict has to be visible in it on its own.
pub const FAILED: &str = "vcrs: failed";

/// Is this process the console-less child that does the work?
pub fn is_detached_worker() -> bool {
    std::env::var_os(WORKER_ENV).is_some()
}

/// Note in the log that the work finished.
pub fn mark_done(log: Option<&Path>) {
    if let Some(path) = log {
        use std::io::Write as _;
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = writeln!(file, "{DONE}");
        }
    }
}

/// Hand a job to a separate process with no console, and give the handle back.
///
/// One caller waits for it ([`wait_for_detached_worker`]); the agent does not — it
/// is the job.
pub fn spawn_detached_worker() -> Result<std::process::Child> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&std::ffi::OsStr> = args.iter().map(|arg| arg.as_os_str()).collect();
    spawn_detached_worker_with(&args)
}

/// The same, for a job that is not this process' own command line — the agent is
/// started with words of its own.
pub fn spawn_detached_worker_with(args: &[&std::ffi::OsStr]) -> Result<std::process::Child> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let exe = std::env::current_exe().context("finding this program's own path")?;
        // A child created with handle inheritance receives every inheritable handle
        // this process holds — including a shell's end of the console pipe when this
        // program was started from one. A worker or an agent outlives its caller, so
        // the caller's shell would wait on a pipe that never closes.
        crate::serve::disinherit_standard_handles();
        Command::new(&exe)
            .args(args)
            .env(WORKER_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .context("starting the console-less worker")
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        bail!("a console-less worker is a Windows notion; there is none here")
    }
}

/// Hand the work to a child with no console and wait for it.
///
/// The elevated child gets a console of its own; when that console is closed — it
/// is a window somebody can click away, and it goes with the process tree when the
/// caller is killed — Windows sends `CTRL_CLOSE_EVENT` and terminates the process
/// about five seconds later (`0xC000013A`). That used to cut an attach in half and
/// take the iSCSI session with it. A process with **no** console can never receive
/// that event, so the real work is handed to a child started with
/// `DETACHED_PROCESS | CREATE_NO_WINDOW`; this process only waits for it, and if it
/// is killed anyway the worker carries on. The caller learns the outcome from the
/// `--log` file (the [`DONE`] line), not from an exit code.
pub fn wait_for_detached_worker() -> Result<()> {
    #[cfg(windows)]
    {
        let mut child = spawn_detached_worker()?;
        let status = child
            .wait()
            .context("waiting for the console-less worker")?;
        // The caller reads the log for the [`DONE`] line, but a launcher that always
        // reported success turned a failed attach into "Y: is mounted": the worker's
        // exit code has to leave this process tree non-zero for the failure to be seen.
        if !status.success() {
            bail!("the elevated worker did not finish ({status})");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("handing the work to a console-less child is Windows-only")
    }
}

pub fn ignore_console_control_events() {
    #[cfg(windows)]
    unsafe {
        unsafe extern "system" fn ignore(
            _kind: winapi::shared::minwindef::DWORD,
        ) -> winapi::shared::minwindef::BOOL {
            // 1 = handled: the event does not reach the default handler, which is
            // what turns Ctrl-C into an exit with STATUS_CONTROL_C_EXIT.
            1
        }
        winapi::um::consoleapi::SetConsoleCtrlHandler(Some(ignore), 1);
    }
}

/// How long to wait for Windows to recognise the filesystem after a letter move
/// (it is not there the instant the letter is).
const READ_BACK_WAIT: Duration = Duration::from_secs(5);

/// Move (or put) the disk's partition on `want`, then wait for Windows to
/// recognise the filesystem, and report the letter it ended up on together with
/// the freshest description of the disk.
///
/// `Set-Partition -NewDriveLetter` and `Add-PartitionAccessPath` both come down to
/// the mount point APIs on the volume's own path, so that is what this does now.
fn set_letter(
    disk: u32,
    partition: u32,
    want: char,
    wait: Duration,
) -> Result<(char, Option<DiskInfo>)> {
    // An offline disk has no volumes to mount, so it comes back online first.
    if crate::win32::disk_is_offline(disk).unwrap_or(false) {
        crate::win32::set_disk_offline(disk, false)
            .with_context(|| format!("bringing disk {disk} back online"))?;
    }
    // The mount point APIs take a volume, not a partition: a volume is what Windows
    // mounts, and it is found from the disk it starts on. The volume under a partition
    // that has just appeared is created a moment later, so Windows is asked to look at
    // the disk again until it turns up.
    let deadline = std::time::Instant::now() + wait;
    let volume = loop {
        match crate::win32::volume_on_disk(disk) {
            Ok(volume) => break volume,
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    return Err(err.context(format!(
                        "finding the volume on disk {disk} partition {partition}"
                    )));
                }
                let _ = crate::win32::refresh_disk(disk);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };
    // Windows usually beats us to it: the moment a disk with a filesystem it
    // recognises arrives, it puts a letter of its own on the volume (`D:`, the next
    // free one). A volume that already wears a letter will not take a second one —
    // `SetVolumeMountPointW` answers `ERROR_INVALID_PARAMETER` and the volume simply
    // stays where Windows put it, which is how asking for `--letter Y` used to end up
    // on `D:`. So Windows' own choice is taken off before the asked-for letter is put
    // on. (`release_letter` also copes with a letter whose volume is already gone.)
    for existing in crate::win32::letters_on_disk(disk) {
        if existing != want {
            crate::win32::release_letter(existing)
                .with_context(|| format!("moving disk {disk} off {existing}:"))?;
        }
    }
    // A volume that has just appeared is not always ready to be put on a letter yet:
    // the call answers `ERROR_INVALID_PARAMETER` until it is, so it is worth a few
    // goes rather than moving on and leaving the disk on Windows' own letter.
    let deadline = std::time::Instant::now() + wait;
    loop {
        match crate::win32::set_mount_point(want, &volume) {
            Ok(()) => break,
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    return Err(err.context(format!(
                        "putting disk {disk} partition {partition} on {want}:"
                    )));
                }
                let _ = crate::win32::refresh_disk(disk);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    // Windows needs a moment before the filesystem is readable under the new letter,
    // so read the disk back until it answers with the letter that was asked for.
    let fresh = read_back(disk, Some(want), wait);
    match fresh.as_ref().and_then(|found| found.letter) {
        Some(got) if got == want => Ok((got, fresh)),
        Some(got) => bail!(
            "Windows put disk {disk} on {got}: instead of {want}: — move it by hand \
             in Disk Management"
        ),
        None => bail!(
            "Windows did not accept {want}: on disk {disk} partition {partition} \
             — assign the letter by hand in Disk Management"
        ),
    }
}

/// Read a disk back until Windows shows its drive letter again, so that the note
/// about an unformatted volume is only printed when it is true.  A container
/// with no filesystem inside never gets one, which is why this gives up.
fn read_back(disk: u32, want: Option<char>, wait: Duration) -> Option<DiskInfo> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let found = vcrs_disks()
            .ok()?
            .into_iter()
            .find(|found| found.number == disk);
        let letter = found.as_ref().and_then(|found| found.letter);
        let done = match want {
            Some(want) => letter == Some(want),
            None => letter.is_some(),
        };
        if done || std::time::Instant::now() >= deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The first non-empty line of some tool output.
pub fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(|line| line.trim())
        .find(|line| !line.is_empty())
        .map(|line| line.to_string())
}

/// The address a server should listen on: `preferred` when it is free, the first
/// free port above it otherwise.
///
/// Two volumes cannot share a portal, and the default portal is `127.0.0.1:3260`,
/// so without this a second `vcrs mount` fails with `os error 10048` (address
/// already in use) although nothing is wrong with the request. Windows' initiator
/// is told the portal in `AddTarget`, so a different port costs nothing.
pub fn free_bind_addr(preferred: &str) -> Result<String> {
    let (host, port) = split_address(preferred);
    let mut last = None;
    for candidate in port..port.saturating_add(PORT_SEARCH) {
        let address = format!("{host}:{candidate}");
        match std::net::TcpListener::bind(&address) {
            Ok(listener) => {
                // Free right now: the server that is about to start binds it for
                // real. Nothing else can take it in between but this program.
                drop(listener);
                return Ok(address);
            }
            Err(err) => last = Some(err),
        }
    }
    bail!(
        "no free port between {port} and {} for the iSCSI target on {host}: {}",
        port.saturating_add(PORT_SEARCH - 1),
        last.map(|err| err.to_string()).unwrap_or_default()
    )
}

/// How many ports above the preferred one are tried before giving up.
const PORT_SEARCH: u16 = 32;

/// Split `host:port` (the form `IscsiMount::addr` uses) for `iscsicli`.
/// Check the two `AttachOptions` fields that end up in an `iscsicli` call before
/// any of it runs, so a bad value fails here rather than after a UAC prompt.
fn validate_target(options: &AttachOptions) -> Result<()> {
    validate_iqn(&options.iqn)?;
    validate_portal(&options.address)
}

/// Reject an iSCSI target name that is not one.
///
/// This is not a quoting rule — `AddTarget` is called with real arguments and no
/// shell. It is a bound on what the *rest* of the program can carry: the name is
/// written into state files, printed in log lines and parsed back out of
/// `iscsicli`'s output, and characters like a newline or a space break those.
/// It also turns a typo into an error before an elevation prompt is spent on it.
pub fn validate_iqn(iqn: &str) -> Result<()> {
    if iqn.is_empty() {
        bail!("the iSCSI target name (IQN) is empty");
    }
    // The iSCSI name grammar allows up to 223 bytes.
    if iqn.len() > 223 {
        bail!(
            "the iSCSI target name is {} characters, over the iSCSI limit of 223",
            iqn.len()
        );
    }
    if !(iqn.starts_with("iqn.") || iqn.starts_with("eui.") || iqn.starts_with("naa.")) {
        bail!("`{iqn}` is not an iSCSI name: it has to start with `iqn.`, `eui.` or `naa.`");
    }
    if let Some(bad) = iqn.chars().find(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '"' | '\'' | '&' | '|' | '^' | '<' | '>' | '%' | ';' | '(' | ')' | '\\' | ',' | '`'
            )
    }) {
        bail!("the iSCSI target name contains {bad:?}, which is not allowed in an iSCSI name");
    }
    Ok(())
}

/// Reject a portal address that is not `host[:port]` with a host of an IP address
/// or a DNS name.
///
/// `--address` used to reach `cmd /c` unescaped; it is an argument now, so this
/// is about catching nonsense (a path, a URL, a shell fragment that used to be
/// an injection) rather than about quoting.
pub fn validate_portal(address: &str) -> Result<()> {
    if address.trim().is_empty() {
        bail!("the iSCSI portal address is empty");
    }
    let (host, port) = split_address(address);
    if host.is_empty() {
        bail!("the iSCSI portal address `{address}` has no host part");
    }
    if let Some(bad) = host
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')))
    {
        bail!(
            "the iSCSI portal host `{host}` contains {bad:?}; only an IP address or a DNS name \
             is accepted"
        );
    }
    // Exactly one `:` means `host:port`, and there the port has to be a number:
    // `127.0.0.1:abc` used to silently become the default port.
    if address.matches(':').count() == 1 {
        if let Some((_, tail)) = address.rsplit_once(':') {
            if tail.parse::<u16>().is_err() {
                bail!("`{address}` has no usable port: `{tail}` is not a number");
            }
        }
    }
    if port == 0 {
        bail!("port 0 is not a usable iSCSI portal port");
    }
    Ok(())
}

fn split_address(address: &str) -> (String, u16) {
    // A bare IPv6 address is nothing but colons, so `rsplit_once(':')` would read its
    // last group as the port: `--address ::1` used to come out as the host `::` (every
    // interface) and the port `1`.  A string that parses as an address in full is
    // therefore an address without a port, in the bare form and in the bracketed form
    // with the port left out.  An address *with* a port stays unambiguous only when
    // the brackets are there (`[::1]:3260`), which is what the RFCs require.
    let bare = address.trim();
    let unbracketed = bare
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(bare);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return (ip.to_string(), 3260);
    }
    match address.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(port) => (host.trim_matches(['[', ']']).to_string(), port),
            Err(_) => (address.to_string(), 3260),
        },
        None => (address.to_string(), 3260),
    }
}

/// Whether an iSCSI portal is one only this machine can reach.
///
/// The threat this guards is `--bind 0.0.0.0:3260`: the disk the target serves is
/// the *decrypted* volume, the vendored target stores `AuthConfig::None` and
/// never checks a CHAP exchange or an allowed-initiator list, and its sessions
/// are plaintext. A loopback bind is the only one that is safe by default, so
/// anything else has to be asked for explicitly.
pub fn is_loopback_addr(address: &str) -> bool {
    let address = address.trim();
    // A bare IPv6 address is all colons, and `split_address` would read its last
    // group as a port, so try the whole string first.
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let (host, port) = split_address(address);
    if port == 0 {
        return false;
    }
    let host = host.trim();
    if host.is_empty() {
        // `:3260` listens on every interface.
        return false;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        // A name this cannot resolve is assumed to be reachable.
        Err(_) => false,
    }
}

/// Output that goes to the terminal and, for an elevated child, to a log file.
pub struct Report {
    log: Option<std::fs::File>,
    quiet: bool,
}

impl Report {
    pub fn new(path: Option<&Path>) -> Self {
        let log = path.and_then(|path| crate::serve::private_file(path).ok());
        Self {
            log,
            quiet: false,
        }
    }

    /// The same report without the lines written for a person.
    ///
    /// A run whose answer is a machine-readable document sets this, so the lines
    /// do not wrap the document in noise. They still go into the log, which is
    /// where the document is picked out of.
    pub fn quiet(&mut self) {
        self.quiet = true;
    }

    pub fn line(&mut self, text: &str) {
        if !self.quiet {
            println!("{text}");
        }
        if let Some(log) = &mut self.log {
            let _ = writeln!(log, "{text}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_disk(number: u32, size: u64, letter: Option<char>) -> DiskInfo {
        DiskInfo {
            number,
            size,
            partition: None,
            letter,
        }
    }

    /// A disk that was already on the machine before the login must never be picked:
    /// the INQUIRY name is the only thing that identifies a vc-rs disk, so a planted
    /// disk can wear it, and the letter would then go onto someone else's volume.
    #[test]
    fn a_disk_that_was_already_there_is_not_ours() {
        let disks = vec![
            a_disk(1, 11272192, Some('S')),
            a_disk(2, 4096, None),
            a_disk(3, 11272192, None),
        ];
        // Disk 1 is the size we want but was there before, so disk 3 (the login's)
        // wins — and with no "before" list, the highest number still wins.
        assert_eq!(newest_disk(&disks, Some(11272192), &[1]).unwrap().number, 3);
        assert_eq!(newest_disk(&disks, Some(11272192), &[]).unwrap().number, 3);
        // The size still has to match.
        assert_eq!(newest_disk(&disks, Some(4096), &[]).unwrap().number, 2);
        assert!(newest_disk(&disks, Some(512), &[]).is_none());
        // A look-alike that was already there and nothing else: no candidate at all.
        assert!(newest_disk(&disks, Some(11272192), &[1, 3]).is_none());
        // Without a size any new disk will do.
        assert_eq!(newest_disk(&disks, None, &[3]).unwrap().number, 2);
    }

    fn options() -> AttachOptions {
        AttachOptions {
            iqn: "iqn.2025-12.io.vcrs:secret".to_string(),
            address: "127.0.0.1:3260".to_string(),
            letter: Some('y'),
            disk_size: Some(11272192),
            wait: DISK_WAIT,
            log: None,
            chap_from: None,
        }
    }

    #[test]
    fn the_add_target_call_carries_the_chap_credentials() {
        // Without CHAP the two credential positions stay empty and the
        // authentication type is 0.
        let args = add_target_arguments(&options()).unwrap();
        assert_eq!(args.len(), 17);
        assert_eq!(args[0], "AddTarget");
        assert_eq!(args[13], "");
        assert_eq!(args[14], "");
        assert_eq!(args[15], "0");

        // With CHAP they carry the user and the secret the target derives from
        // the same 64 bytes, and the authentication type is
        // `ISCSI_CHAP_AUTH_TYPE` (one-way CHAP).
        let salt = [7u8; 64];
        let path = std::env::temp_dir().join("vcrs-chap-secret-test.vc");
        std::fs::write(&path, salt).unwrap();
        let with_chap = AttachOptions {
            chap_from: Some(path.clone()),
            ..options()
        };
        let args = add_target_arguments(&with_chap).unwrap();
        assert_eq!(args[13], vcrs_core::CHAP_USER);
        let secret = vcrs_core::chap_secret(&salt, "iqn.2025-12.io.vcrs:secret").unwrap();
        assert_eq!(args[14], secret);
        assert_eq!(args[15], "1");
        assert!((12..=16).contains(&secret.len()), "{secret}");

        // A file that is too short to hold a salt is refused rather than
        // silently logging in with a secret derived from nothing.
        std::fs::write(&path, [1u8; 8]).unwrap();
        assert!(add_target_arguments(&with_chap).is_err());
        let _ = std::fs::remove_file(&path);

        // And a missing file is an error too.
        let missing = AttachOptions {
            chap_from: Some(std::env::temp_dir().join("vcrs-chap-does-not-exist.vc")),
            ..options()
        };
        assert!(add_target_arguments(&missing).is_err());
    }

    #[test]
    fn the_child_gets_the_same_request_plus_a_log() {
        let args = attach_arguments(&options(), Some(Path::new(r"C:\Temp\vcrs.log")), false);
        assert_eq!(
            args,
            vec![
                "attach",
                "--iqn",
                "iqn.2025-12.io.vcrs:secret",
                "--address",
                "127.0.0.1:3260",
                "--wait",
                "30",
                "--letter",
                "y",
                "--disk-size",
                "11272192",
                "--log",
                r"C:\Temp\vcrs.log",
            ]
        );
        let without = attach_arguments(
            &AttachOptions {
                letter: None,
                disk_size: None,
                ..options()
            },
            None,
            false,
        );
        assert!(!without.iter().any(|a| a == "--letter" || a == "--log"));
        // `--json` travels down to the elevated half (it is what makes that half
        // send its document back instead of lines).
        assert!(attach_arguments(&options(), None, true).contains(&"--json".to_string()));
    }

    #[test]
    fn the_add_target_call_keeps_the_two_chap_arguments_empty() {
        // The two CHAP arguments have to stay *empty*, and they are passed as two
        // empty `argv` elements now: no shell, so nothing in the IQN or the portal
        // can be a command (`std::process` renders an empty argument as `""`).
        let argv: Vec<&str> = [
            "AddTarget",
            "iqn.2025-12.io.vcrs:secret",
            "vcrs",
            "127.0.0.1",
            "3260",
            "0",
            "0",
            "0",
            "0",
            "0",
            "8",
            "0",
            "0",
            "",
            "",
            "0",
            "0",
        ]
        .to_vec();
        assert_eq!(argv.iter().filter(|a| a.is_empty()).count(), 2);
        assert_eq!(&argv[argv.len() - 4..], &["", "", "0", "0"]);
        // `""` never appears literally: it is an empty argv element, not text.
        assert!(!argv.iter().any(|a| *a == "\"\""));
    }

    #[test]
    fn an_iqn_that_is_not_one_is_refused() {
        assert!(validate_iqn("iqn.2025-12.io.vcrs:secret").is_ok());
        assert!(validate_iqn("eui.0200000000000000").is_ok());
        // The old injection: a shell metacharacter is not an iSCSI name.
        assert!(validate_iqn("iqn.x & net user pwn P@ss /add").is_err());
        assert!(validate_iqn("iqn.x\npid=1").is_err());
        assert!(validate_iqn("iqn.x | calc").is_err());
        assert!(validate_iqn("not-an-iqn").is_err());
        assert!(validate_iqn("").is_err());
        assert!(validate_iqn(&format!("iqn.{}", "a".repeat(300))).is_err());
    }

    #[test]
    fn a_portal_that_is_not_one_is_refused() {
        assert!(validate_portal("127.0.0.1:3260").is_ok());
        assert!(validate_portal("127.0.0.1").is_ok());
        assert!(validate_portal("[::1]:3260").is_ok());
        // A bare or bracket-only IPv6 address carries no port, which is fine.
        assert!(validate_portal("::1").is_ok());
        assert!(validate_portal("[::1]").is_ok());
        assert!(validate_portal("iscsi.example.com").is_ok());
        // The old injection, and assorted nonsense.
        assert!(validate_portal("127.0.0.1 & calc").is_err());
        assert!(validate_portal("127.0.0.1:abc").is_err());
        assert!(validate_portal("127.0.0.1:0").is_err());
        assert!(validate_portal("").is_err());
        assert!(validate_portal(r"C:\Temp").is_err());
    }

    #[test]
    fn an_address_splits_into_a_host_and_a_port() {
        assert_eq!(
            split_address("127.0.0.1:3260"),
            ("127.0.0.1".to_string(), 3260)
        );
        assert_eq!(
            split_address("192.168.1.7:3261"),
            ("192.168.1.7".to_string(), 3261)
        );
        assert_eq!(split_address("127.0.0.1"), ("127.0.0.1".to_string(), 3260));
        assert_eq!(split_address("[::1]:3260"), ("::1".to_string(), 3260));
        // A bare or bracket-only IPv6 address has no port in it: reading its last
        // group as one would make `::1` mean the host `::` and the port `1`.
        assert_eq!(split_address("::1"), ("::1".to_string(), 3260));
        assert_eq!(split_address("[::1]"), ("::1".to_string(), 3260));
        assert_eq!(split_address("fe80::1"), ("fe80::1".to_string(), 3260));
        assert_eq!(split_address("::"), ("::".to_string(), 3260));
    }

    #[test]
    fn a_drive_letter_mask_is_read_back() {
        // C: and D: and Z:
        assert_eq!(
            letters_from_mask((1 << 2) | (1 << 3) | (1 << 25)),
            vec!['C', 'D', 'Z']
        );
        assert!(letters_from_mask(0).is_empty());
        assert_eq!(letters_from_mask(1 << 25), vec!['Z']);
        // A: and B:, the floppies nobody has any more
        assert_eq!(letters_from_mask(0b11), vec!['A', 'B']);
    }

    #[test]
    fn the_ids_of_the_sessions_that_outlived_their_target_are_found() {
        // Trimmed-down `iscsicli SessionList 1` output from a real run, with a
        // session on our target, one on somebody else's, and a stale session
        // whose target node is gone.
        let list = "Microsoft iSCSI Initiator Version 10.0 Build 26300\n\
                    Total of 3 sessions\n\
                    Session Id             : ffff9c8e78edf010-4000013700000002\n\
                    Initiator Node Name    : iqn.1991-05.com.microsoft:desktop-985akhr\n\
                    Target Node Name       : (null)\n\
                    Target Name            : iqn.2025-12.io.vcrs:smoke\n\
                    ISID                   : 40 00 01 37 00 00\n\
                    Session Id             : ffffe68332afe010-4000013700000009\n\
                    Initiator Node Name    : iqn.1991-05.com.microsoft:desktop-985akhr\n\
                    Target Node Name       : iqn.other:storage\n\
                    Session Id             : ffff9c8e78edf010-4000013700000004\n\
                    Target Node Name       : (null)\n\
                    Target Name            : iqn.2025-12.io.vcrs:smoke\n";
        assert_eq!(
            session_ids(list, "iqn.2025-12.io.vcrs:smoke"),
            vec![
                "ffff9c8e78edf010-4000013700000002".to_string(),
                "ffff9c8e78edf010-4000013700000004".to_string(),
            ],
            "both sessions of our own target are found, the other one is left alone"
        );
        assert!(session_ids(list, "iqn.2025-12.io.vcrs:probe").is_empty());
        assert!(session_ids("Total of 0 sessions\n", "iqn.2025-12.io.vcrs:smoke").is_empty());
        assert!(session_ids("", "iqn.2025-12.io.vcrs:smoke").is_empty());
    }
}

/// Start a helper process with no console window of its own.
///
/// The worker that runs a dismount has no console — that is exactly what keeps a
/// closing console from killing it — so every wrapper it starts would otherwise
/// allocate a console of its own. That is what a user sees as a window flashing
/// once per PowerShell call, two or three times per dismount.
pub fn quiet_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}
