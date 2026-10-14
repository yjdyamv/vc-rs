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
}

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

    // 2. register the target statically, then log in.  The two empty CHAP
    //    arguments only survive as `""` through a `cmd /c` hop, which is why
    //    this one command is built as a line rather than as arguments.
    let (host, port) = split_address(&options.address);
    let add = format!(
        "iscsicli AddTarget {} vcrs {} {} 0 0 0 0 0 8 0 0 \"\" \"\" 0 0",
        options.iqn, host, port
    );
    iscsicli_line(&add).with_context(|| format!("registering {host}:{port} as a static target"))?;
    if let Ok(out) = iscsicli(&["QLoginTarget", &options.iqn]) {
        report.line(&first_line(&out).unwrap_or_else(|| "logged in".to_string()));
    }
    report.line(&format!(
        "logged in to {}; waiting up to {} s for Windows to show the disk",
        options.iqn,
        options.wait.as_secs()
    ));

    // 3. Windows builds the disk asynchronously, so wait for it to turn up.
    let disk = wait_for_disk(options.disk_size, options.wait, &mut report)?;

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
    let disk = fresher
        .or_else(|| read_back(disk.number, READ_BACK_WAIT))
        .unwrap_or(disk);
    let has_file_system = disk
        .partition
        .as_ref()
        .map(|p| p.file_system.is_some())
        .unwrap_or(false);
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
pub fn attach_with_elevation(options: &AttachOptions) -> Result<()> {
    if elevated() {
        attach(options)?;
        return Ok(());
    }

    let exe = std::env::current_exe().context("finding this program's own path")?;
    let log = temp_log_path();
    let args = attach_arguments(options, Some(&log));
    println!(
        "attaching {} needs an elevated prompt (iscsicli carries a requireAdministrator manifest):",
        options.iqn
    );
    println!(
        "  approving the Windows prompt that is about to appear …  (or run `vcrs attach {}` \
         yourself from an elevated prompt)",
        options.iqn
    );
    let code = start_elevated(&exe, &args, &log)?;
    replay_elevated(code, &log, "attach")
}

/// Read back what an elevated child wrote, then judge its exit code.
///
/// The child has a console of its own, so its output comes back through the log
/// file it was told to write.
pub(crate) fn replay_elevated(code: i32, log: &Path, what: &str) -> Result<()> {
    match std::fs::read_to_string(log) {
        Ok(text) => print!("{text}"),
        Err(err) => println!("  (the elevated run left no log to read: {err})"),
    }
    let _ = std::fs::remove_file(log);
    if code != 0 {
        bail!("the elevated {what} did not succeed (exit code {code})");
    }
    Ok(())
}

/// Exit code `Start-Process -Verb RunAs` reports when the user refuses UAC.
pub(crate) const ELEVATION_CANCELLED: i32 = 1223;

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
fn attach_arguments(options: &AttachOptions, log: Option<&Path>) -> Vec<String> {
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
    if let Some(log) = log {
        args.push("--log".to_string());
        args.push(log.display().to_string());
    }
    args
}

pub(crate) fn temp_log_path() -> PathBuf {
    std::env::temp_dir().join(format!("vcrs-attach-{}.log", std::process::id()))
}

/// Run `exe args` elevated and wait for it, returning its exit code.
///
/// `Start-Process -Verb RunAs` is the only supported way to ask for elevation
/// from a normal process, and `-Wait -PassThru` still gives back the child's
/// exit code.
pub(crate) fn start_elevated(exe: &Path, args: &[String], _log: &Path) -> Result<i32> {
    let list: Vec<String> = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "''")))
        .collect();
    let script = format!(
        "$ErrorActionPreference = 'Stop'\ntry {{ $p = Start-Process -FilePath '{exe}' \
         -ArgumentList @({list}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode }} \
         catch {{ Write-Error $_; exit {ELEVATION_CANCELLED} }}",
        exe = exe.display().to_string().replace('\'', "''"),
        list = list.join(","),
    );
    // The elevator gets none of our handles: `Start-Process -Wait` waits for the
    // elevated process *and its children*, and an inherited stdout pipe would keep
    // the caller's shell waiting for a volume that is already mounted. The elevated
    // child writes its result into `--log`, which the caller replays.
    let out = Command::new("powershell")
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
        bail!("elevation was refused, so nothing was attached");
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
pub(crate) fn letter_argument(letter: char) -> Result<char> {
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
/// Remove the disk device nodes Windows keeps for vc-rs volumes it made earlier,
/// which is what frees an iSCSI session the initiator will not log out while its
/// device is still held by the storage stack.
pub(crate) fn forget_stale_devices(report: &mut Report) {
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
pub(crate) fn iscsicli(args: &[&str]) -> Result<String> {
    let out = Command::new("iscsicli")
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
    if !out.status.success() && !all.to_ascii_lowercase().contains("already") {
        bail!(
            "`iscsicli {}` failed ({}): {}",
            args.join(" "),
            out.status,
            all.trim()
        );
    }
    Ok(all)
}

/// Run a whole `iscsicli` command line through `cmd /c`.
///
/// `AddTarget` takes two arguments that must stay *empty* (the CHAP user and
/// password); passing them as empty strings straight to `CreateProcess` loses
/// them, so the line goes through `cmd`, which keeps the literal `""`.
fn iscsicli_line(line: &str) -> Result<String> {
    let out = Command::new("cmd")
        .args(["/c", line])
        .output()
        .with_context(|| format!("running `{line}`"))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let errors = String::from_utf8_lossy(&out.stderr);
    let mut all = text;
    if !errors.trim().is_empty() {
        all.push_str(errors.trim());
        all.push('\n');
    }
    if !out.status.success() {
        bail!("`{line}` failed ({}): {}", out.status, all.trim());
    }
    Ok(all)
}

/// Run a PowerShell one-liner and give back its output.
pub(crate) fn powershell(script: &str) -> Result<String> {
    let out = Command::new("powershell")
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
fn ensure_initiator_service(report: &mut Report) -> Result<()> {
    let query = "(Get-Service -Name msiscsi).Status.ToString()";
    let status = powershell(query)?.trim().to_ascii_lowercase();
    if status == "running" {
        return Ok(());
    }
    report.line(&format!(
        "the Microsoft iSCSI Initiator Service is {status}; starting it"
    ));
    powershell("Start-Service -Name msiscsi")?;
    let deadline = Instant::now() + SERVICE_START_WAIT;
    loop {
        let status = powershell(query)?.trim().to_ascii_lowercase();
        if status == "running" {
            report.line("the iSCSI service is up");
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the Microsoft iSCSI Initiator Service did not start (it is still {status}); \
                 start it by hand with `sc start msiscsi`"
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
/// One PowerShell pass: `Get-Disk` finds the disks by their INQUIRY product
/// string, `Get-Partition` gives the partition and its letter, and
/// `Win32_LogicalDisk` gives the filesystem (the deleted GUI learned that
/// `Get-Volume` reports an empty filesystem for some freshly attached disks).
pub(crate) fn vcrs_disks() -> Result<Vec<DiskInfo>> {
    let script = disks_script(None, None, true);
    Ok(parse_disks(&powershell(&script)?))
}

/// PowerShell that describes the disk in `$d` as one `disk=…` row.
///
/// Kept in one place so the three callers that need a disk described (listing
/// them, waiting for one, moving a letter) cannot drift apart.
fn row_code() -> String {
    "$p = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | \
     Select-Object -First 1; \
     $fs = ''; $text_letter = ''; \
     if ($p) { if ($p.DriveLetter) { $text_letter = $p.DriveLetter; \
       $fs = (Get-Volume -DriveLetter $text_letter -ErrorAction SilentlyContinue).FileSystem; \
       if (-not $fs) { \
         $fs = (Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='$text_letter':\" \
           -ErrorAction SilentlyContinue).FileSystem } } }; \
     'disk={0};size={1};part={2};letter={3};fs={4}' -f \
       $d.Number, $d.Size, $(if ($p) { $p.PartitionNumber } else { 0 }), \
       $text_letter, $(if ($fs) { $fs } else { '' })"
        .to_string()
}

/// PowerShell for the vc-rs disks.
///
/// With `wait` the polling loop runs *inside* PowerShell: every process this
/// spawns costs about a second, so polling from Rust every 500 ms cost far more
/// than the disk takes to appear. With `all` false only the newest disk of the
/// wanted size is described (that is the one Windows has just created); with
/// `all` true every vc-rs disk is.
pub(crate) fn disks_script(wait: Option<Duration>, size: Option<u64>, all: bool) -> String {
    let want = size.unwrap_or(0);
    let body = if all {
        format!(
            "Get-Disk | Where-Object {{ $_.FriendlyName -like '*{DISK_NAME}*' }} | \
             ForEach-Object {{ $d = $_; {} }}",
            row_code()
        )
    } else {
        format!(
            "$d = Get-Disk | Where-Object {{ $_.FriendlyName -like '*{DISK_NAME}*' -and \
               ({want} -eq 0 -or $_.Size -eq {want}) }} | \
             Sort-Object Number -Descending | Select-Object -First 1; \
             if ($d) {{ {} }}",
            row_code(),
            want = want
        )
    };
    // `Update-HostStorageCache` is what makes a disk the initiator has just
    // logged in show up: without it Windows keeps serving the disk list it had
    // before the login, and a freshly attached volume looks like it never
    // arrived (the same call the iSCSI end-to-end script makes in its poll).
    let pass = format!("Update-HostStorageCache -ErrorAction SilentlyContinue; {body}");
    match wait {
        None => pass,
        Some(timeout) => format!(
            "$deadline = (Get-Date).AddSeconds({}); do {{ {} \
             if ($d) {{ break }}; Start-Sleep -Milliseconds 400 }} while ((Get-Date) -lt $deadline)",
            timeout.as_secs_f64(),
            pass
        ),
    }
}

/// Read the `disk=…;size=…;part=…;letter=…;fs=…` lines [`vcrs_disks`] emits.
pub(crate) fn parse_disks(text: &str) -> Vec<DiskInfo> {
    let mut disks: Vec<DiskInfo> = Vec::new();
    for line in text.lines() {
        let mut disk_number = None;
        let mut size = None;
        let mut part_number = None;
        let mut letter = None;
        let mut fs = None;
        for field in line.trim().split(';') {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "disk" => disk_number = value.parse().ok(),
                "size" => size = value.parse().ok(),
                "part" => part_number = value.parse().ok(),
                "letter" => letter = value.chars().next().filter(|c| c.is_ascii_alphabetic()),
                "fs" => {
                    let value = value.trim();
                    fs = (!value.is_empty()).then(|| value.to_string());
                }
                _ => {}
            }
        }
        let (Some(number), Some(size)) = (disk_number, size) else {
            continue;
        };
        let partition = part_number.filter(|n| *n > 0).map(|number| PartitionInfo {
            number,
            letter,
            file_system: fs.clone(),
        });
        disks.push(DiskInfo {
            number,
            size,
            partition,
            letter: letter.map(|c| c.to_ascii_uppercase()),
        });
    }
    disks
}

/// Wait for the disk Windows creates for the target to show up.
///
/// The disk is chosen by its INQUIRY name, and by size when the caller knows it
/// (several `vcrs mount` processes can be serving different volumes at once);
/// the highest disk number wins when two of them are the same size, because
/// Windows numbers a newly created disk above the existing ones.
fn wait_for_disk(
    disk_size: Option<u64>,
    timeout: Duration,
    report: &mut Report,
) -> Result<DiskInfo> {
    report.line(&format!(
        "waiting up to {} s for the disk …",
        timeout.as_secs()
    ));
    let text = powershell(&disks_script(Some(timeout), disk_size, false))?;
    if let Some(disk) = parse_disks(&text).into_iter().next() {
        return Ok(disk);
    }
    // Nothing appeared: say what Windows does have, which is what tells a stale
    // device apart from a login that never got through.
    let seen: Vec<String> = vcrs_disks()
        .unwrap_or_default()
        .iter()
        .map(|disk| format!("disk {} ({} bytes)", disk.number, disk.size))
        .collect();
    bail!(
        "Windows did not show the disk within {} s{}. \
         `vcrs dismount --iscsi <IQN>` clears a half-finished attach",
        timeout.as_secs(),
        if seen.is_empty() {
            String::new()
        } else {
            format!("; the vc-rs disks it does have: {}", seen.join(", "))
        },
    );
}

/// Make this process ignore console control events (Ctrl-C, Ctrl-Break, a
/// closing console).
///
/// Set in the child that really does the work (see [`run_detached_worker`]).
pub(crate) const WORKER_ENV: &str = "VCRS_ELEVATED_WORKER";

/// The line that says the work finished, written into the `--log` file: the caller
/// reads it back, so a launcher that was killed while waiting cannot make a
/// successful job look failed.
pub(crate) const DONE: &str = "vcrs: done";

/// Is this process the console-less child that does the work?
pub(crate) fn is_detached_worker() -> bool {
    std::env::var_os(WORKER_ENV).is_some()
}

/// Note in the log that the work finished.
pub(crate) fn mark_done(log: Option<&Path>) {
    if let Some(path) = log {
        use std::io::Write as _;
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = writeln!(file, "{DONE}");
        }
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
pub(crate) fn wait_for_detached_worker() -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let exe = std::env::current_exe().context("finding this program's own path")?;
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        let mut child = Command::new(&exe)
            .args(&args)
            .env(WORKER_ENV, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .context("starting the console-less worker")?;
        child
            .wait()
            .context("waiting for the console-less worker")?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("handing the work to a console-less child is Windows-only")
    }
}

pub(crate) fn ignore_console_control_events() {
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
/// the freshest description of the disk. One PowerShell process, because each
/// one costs about a second.
fn set_letter(
    disk: u32,
    partition: u32,
    want: char,
    wait: Duration,
) -> Result<(char, Option<DiskInfo>)> {
    // `Set-Partition -NewDriveLetter` moves a letter a partition already has and
    // also sets the first one; an access path is the fallback, and it has to be
    // spelled `Y:\` — `Remove-PartitionAccessPath -DriveLetter` refuses the
    // disk-and-partition parameter set.
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$d = Get-Disk -Number {disk} -ErrorAction SilentlyContinue
if ($d -and $d.IsOffline) {{ Set-Disk -Number {disk} -IsOffline $false }}
$p = Get-Partition -DiskNumber {disk} -PartitionNumber {partition}
if ($p.DriveLetter -ne '{want}') {{
  if ($p.DriveLetter) {{
    try {{ Set-Partition -DiskNumber {disk} -PartitionNumber {partition} -NewDriveLetter {want} -ErrorAction Stop }}
    catch {{
      Remove-PartitionAccessPath -DiskNumber {disk} -PartitionNumber {partition} -AccessPath ($p.DriveLetter.ToString() + ':\')
      Add-PartitionAccessPath -DiskNumber {disk} -PartitionNumber {partition} -AccessPath '{want}:\'
    }}
  }} else {{
    Add-PartitionAccessPath -DiskNumber {disk} -PartitionNumber {partition} -AccessPath '{want}:\'
  }}
}}
$deadline = (Get-Date).AddSeconds({wait})
$row = ''
do {{
  Update-HostStorageCache -ErrorAction SilentlyContinue
  $d = Get-Disk -Number {disk} -ErrorAction SilentlyContinue
  if ($d) {{ $row = {row} }}
  if ($row -match 'fs=.+$') {{ break }}
  Start-Sleep -Milliseconds 300
}} while ((Get-Date) -lt $deadline)
$row
'letter={want}'"#,
        disk = disk,
        partition = partition,
        want = want,
        wait = wait.as_secs_f64(),
        row = row_code()
    );
    let text = powershell(&script)
        .with_context(|| format!("putting disk {disk} partition {partition} on {want}:"))?;
    let got = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("letter="))
        .and_then(|value| value.trim().chars().next())
        .map(|c| c.to_ascii_uppercase());
    let fresh = parse_disks(&text)
        .into_iter()
        .find(|found| found.number == disk);
    match got {
        Some(got) => Ok((got, fresh)),
        None => bail!(
            "Windows did not accept {want}: on disk {disk} partition {partition} \
             — assign the letter by hand in Disk Management"
        ),
    }
}

/// Read a disk back until Windows reports a filesystem on it, so that the note
/// about an unformatted volume is only printed when it is true.  A container
/// with no filesystem inside never gets one, which is why this gives up.
fn read_back(disk: u32, wait: Duration) -> Option<DiskInfo> {
    let script = format!(
        "$deadline = (Get-Date).AddSeconds({}); $row = ''; \
         do {{ Update-HostStorageCache -ErrorAction SilentlyContinue; \
           $d = Get-Disk -Number {disk} -ErrorAction SilentlyContinue; \
           if ($d) {{ $row = {} }}; \
           if ($row -match 'fs=.+$') {{ break }}; \
           Start-Sleep -Milliseconds 300 }} while ((Get-Date) -lt $deadline); \
         $row",
        wait.as_secs_f64(),
        row_code()
    );
    let text = powershell(&script).ok()?;
    parse_disks(&text)
        .into_iter()
        .find(|found| found.number == disk)
}

/// The first non-empty line of some tool output.
pub(crate) fn first_line(text: &str) -> Option<String> {
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
pub(crate) fn free_bind_addr(preferred: &str) -> Result<String> {
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
fn split_address(address: &str) -> (String, u16) {
    match address.rsplit_once(':') {
        Some((host, port)) => match port.parse() {
            Ok(port) => (host.trim_matches(['[', ']']).to_string(), port),
            Err(_) => (address.to_string(), 3260),
        },
        None => (address.to_string(), 3260),
    }
}

/// Output that goes to the terminal and, for an elevated child, to a log file.
pub(crate) struct Report {
    log: Option<std::fs::File>,
}

impl Report {
    pub(crate) fn new(path: Option<&Path>) -> Self {
        let log = path.and_then(|path| std::fs::File::create(path).ok());
        Self { log }
    }

    pub(crate) fn line(&mut self, text: &str) {
        println!("{text}");
        if let Some(log) = &mut self.log {
            let _ = writeln!(log, "{text}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> AttachOptions {
        AttachOptions {
            iqn: "iqn.2025-12.io.vcrs:secret".to_string(),
            address: "127.0.0.1:3260".to_string(),
            letter: Some('y'),
            disk_size: Some(11272192),
            wait: DISK_WAIT,
            log: None,
        }
    }

    #[test]
    fn the_child_gets_the_same_request_plus_a_log() {
        let args = attach_arguments(&options(), Some(Path::new(r"C:\Temp\vcrs.log")));
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
        );
        assert!(!without.iter().any(|a| a == "--letter" || a == "--log"));
    }

    #[test]
    fn the_manual_path_never_splits_the_chap_arguments() {
        // The line handed to `cmd /c` must still carry the two empty strings.
        let line = format!(
            "iscsicli AddTarget {} vcrs {} {} 0 0 0 0 0 8 0 0 \"\" \"\" 0 0",
            "iqn.2025-12.io.vcrs:secret", "127.0.0.1", 3260
        );
        assert_eq!(line.matches("\"\"").count(), 2);
        assert!(line.ends_with("\"\" \"\" 0 0"), "{line}");
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
    fn the_disk_lines_powershell_prints_are_read_back() {
        let text = "disk=3;size=11272192;part=1;letter=F;fs=NTFS\ndisk=4;size=2147483648;part=0;letter=;fs=\n";
        let disks = parse_disks(text);
        assert_eq!(disks.len(), 2);
        assert_eq!(
            disks[0],
            DiskInfo {
                number: 3,
                size: 11272192,
                partition: Some(PartitionInfo {
                    number: 1,
                    letter: Some('F'),
                    file_system: Some("NTFS".to_string()),
                }),
                letter: Some('F'),
            }
        );
        // A disk Windows has not partitioned yet: no partition, no letter.
        assert_eq!(
            disks[1],
            DiskInfo {
                number: 4,
                size: 2147483648,
                partition: None,
                letter: None,
            }
        );
        // Noise (a warning banner, an empty line) is ignored.
        assert!(parse_disks("Get-Partition : Access is denied\n\n").is_empty());
    }

    #[test]
    fn a_mounted_but_unformatted_disk_has_no_file_system() {
        let disks = parse_disks("disk=5;size=535756800;part=1;letter=G;fs=\n");
        let partition = disks[0].partition.clone().unwrap();
        assert_eq!(partition.letter, Some('G'));
        assert_eq!(partition.file_system, None);
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
