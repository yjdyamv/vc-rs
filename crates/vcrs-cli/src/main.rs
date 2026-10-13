//! `vcrs` — command line front end for the vc-rs VeraCrypt implementation.
//!
//! The commands mirror what is needed to check the on-disk format against real
//! VeraCrypt: create volumes, inspect headers, and read/write raw volume data.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use vcrs_core::header::{
    HEADER_ENCRYPTED_DATA_OFFSET, MASTER_KEY_AREA_OFFSET, VOLUME_HEADER_SIZE, VOLUME_HEADER_SIZE_LEGACY,
};
use vcrs_core::volume::{CreateOptions, OpenOptions, Volume};
use vcrs_core::{EncryptionAlgorithm, Prf, VolumeLayout, VolumeType};

#[derive(Parser)]
#[command(name = "vcrs", version, about = "VeraCrypt-compatible volume tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new VeraCrypt-format volume (V2 normal volume).
    Create(CreateArgs),
    /// Create a hidden volume inside an existing volume file.
    CreateHidden(CreateHiddenArgs),
    /// Open a volume and print its header fields.
    Info(InfoArgs),
    /// Print the raw (still encrypted) header bytes of a volume file.
    Header(HeaderArgs),
    /// Read decrypted data from a volume.
    Read(ReadArgs),
    /// Write data into a volume.
    Write(WriteArgs),
    /// Create a FAT filesystem inside an existing volume's data area.
    Format(FormatArgs),
    /// Mount a volume: expose its data area as a raw block device over iSCSI,
    /// so the initiator's own drivers mount (and can format) the filesystem
    /// inside it. Needs an elevated prompt to log the target in.
    Mount(MountArgs),
    /// Detach a volume mounted with `vcrs mount` from the iSCSI initiator.
    Dismount(DismountArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// Volume file to create (must not exist).
    path: PathBuf,
    /// Volume size, e.g. `100M`, `4G`, or a byte count.
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    /// Encryption algorithm, e.g. `AES`, `Serpent-AES`, `AES-Twofish-Serpent`.
    #[arg(short, long, default_value = "AES")]
    ea: String,
    /// Header key derivation function, e.g. `SHA-512`, `Blake2s`, `Argon2`.
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    /// Write random-looking data over the whole data area (VeraCrypt "full" format).
    #[arg(long)]
    full: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct CreateHiddenArgs {
    /// Existing volume file to add a hidden volume to.
    path: PathBuf,
    /// Size of the hidden volume.
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    #[arg(short, long, default_value = "AES")]
    ea: String,
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args, Clone)]
struct PasswordArgs {
    /// Volume password.
    #[arg(short, long, env = "VCRS_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Read the password from stdin (raw bytes, one trailing newline trimmed).
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
    /// Personal iterations multiplier (0 = VeraCrypt default).
    #[arg(long, default_value_t = 0)]
    pim: i32,
}

impl PasswordArgs {
    fn read(&self) -> Result<Vec<u8>> {
        if self.password_stdin {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
            }
            return Ok(buf);
        }
        let p = self
            .password
            .clone()
            .context("no password given (use --password, $VCRS_PASSWORD or --password-stdin)")?;
        Ok(p.into_bytes())
    }
}

#[derive(Args)]
struct FormatArgs {
    /// Volume file holding the filesystem.
    path: PathBuf,
    /// FAT flavour to create.
    #[arg(long, value_parser = ["auto", "fat16", "fat32"], default_value = "auto")]
    fat: String,
    /// Volume label (max 11 characters).
    #[arg(long, default_value = "")]
    label: String,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct MountArgs {
    /// Volume file to mount.
    path: PathBuf,
    /// How the disk is presented to the initiator: `partition` (default; the
    /// data area is exposed as one partition behind a synthetic in-memory MBR,
    /// which is what Windows needs to format it) or `raw` (the data area starts
    /// at LBA 0, i.e. a partitionless "super floppy").
    #[arg(
        long,
        aliases = ["iscsi", "raw"],
        value_name = "MODE",
        num_args = 0..=1,
        default_missing_value = "partition"
    )]
    disk_mode: Option<String>,
    /// Report the disk as removable media (the INQUIRY RMB bit).
    ///
    /// Windows only offers exFAT in its format dialogs for removable media, so
    /// this is how to get exFAT into that list.
    #[arg(long)]
    removable: bool,
    /// Address the iSCSI target listens on (default `127.0.0.1:3260`).
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,
    /// IQN the iSCSI target is published under.
    #[arg(long, value_name = "IQN")]
    target_name: Option<String>,
    /// Refuse all writes.
    #[arg(long)]
    read_only: bool,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct DismountArgs {
    /// IQN of the target started by `vcrs mount` (list the attached ones with
    /// `iscsicli SessionList 1`).
    #[arg(
        long,
        value_name = "IQN",
        num_args = 0..=1,
        default_missing_value = "iqn.2025-12.io.vcrs:volume"
    )]
    iscsi: Option<String>,
}

/// Selects which volume of a container to address.
#[derive(Args, Clone, Copy, Default)]
struct VolumeKindArgs {
    /// Address the hidden volume instead of the outer one.
    #[arg(long)]
    hidden: bool,
}

impl VolumeKindArgs {
    fn volume_type(&self) -> Option<VolumeType> {
        if self.hidden {
            Some(VolumeType::Hidden)
        } else {
            None
        }
    }
}

#[derive(Args)]
struct InfoArgs {
    path: PathBuf,
    /// Open the backup header (at the end of the file) instead of the primary one.
    #[arg(long)]
    backup: bool,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct HeaderArgs {
    path: PathBuf,
    /// Dump the backup header region instead of the primary one.
    #[arg(long)]
    backup: bool,
    /// Only print the 512-byte effective header.
    #[arg(long)]
    short: bool,
}

#[derive(Args)]
struct ReadArgs {
    path: PathBuf,
    /// Offset inside the encrypted data area.
    #[arg(short, long, default_value_t = 0)]
    offset: u64,
    /// Number of bytes to read.
    #[arg(short, long, default_value_t = 512, value_parser = parse_size)]
    length: u64,
    /// Write the bytes to this file instead of dumping them.
    #[arg(long)]
    out: Option<PathBuf>,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct WriteArgs {
    path: PathBuf,
    /// Offset inside the encrypted data area.
    #[arg(short, long, default_value_t = 0)]
    offset: u64,
    /// Bytes to write, as hex (leading 0x optional).
    #[arg(long)]
    hex: Option<String>,
    /// Read the bytes to write from this file.
    #[arg(long, conflicts_with = "hex")]
    from: Option<PathBuf>,
    #[command(flatten)]
    kind: VolumeKindArgs,
    #[command(flatten)]
    password: PasswordArgs,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vcrs: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Create(a) => {
            let ea = parse_ea(&a.ea)?;
            let prf = parse_prf(&a.prf)?;
            let options = CreateOptions {
                ea,
                prf,
                password: a.password.read()?,
                pim: a.password.pim,
                sector_size: 512,
                full_format: a.full,
            };
            let started = std::time::Instant::now();
            let volume = Volume::create(&a.path, a.size, &options)?;
            println!(
                "created {} ({}, {:.2} MiB) in {:.2}s",
                a.path.display(),
                ea.name(),
                a.size as f64 / (1024.0 * 1024.0),
                started.elapsed().as_secs_f64()
            );
            print_header(&volume);
            Ok(())
        }
        Command::CreateHidden(a) => {
            let options = CreateOptions {
                ea: parse_ea(&a.ea)?,
                prf: parse_prf(&a.prf)?,
                password: a.password.read()?,
                pim: a.password.pim,
                sector_size: 512,
                full_format: false,
            };
            let started = std::time::Instant::now();
            let volume = Volume::create_hidden(&a.path, a.size, &options)
                .context("creating a hidden volume inside the existing container")?;
            println!(
                "created a {} hidden volume in {} in {:.2}s",
                volume.header.ea.name(),
                a.path.display(),
                started.elapsed().as_secs_f64()
            );
            print_header(&volume);
            Ok(())
        }
        Command::Info(a) => {
            let options = OpenOptions {
                password: a.password.read()?,
                pim: a.password.pim,
                volume_type: a.kind.volume_type(),
                use_backup_header: a.backup,
                ..Default::default()
            };
            let volume = Volume::open(&a.path, &options)?;
            print_header(&volume);
            Ok(())
        }
        Command::Header(a) => dump_header_region(&a),
        Command::Read(a) => {
            let password = a.password.read()?;
            let volume = open_ro(&a.path, password, a.password.pim, a.kind.volume_type())?;
            let mut buf = vec![0u8; a.length as usize];
            volume.read_data(a.offset, &mut buf)?;
            if let Some(out) = a.out {
                std::fs::write(&out, &buf)?;
                println!("wrote {} bytes to {}", buf.len(), out.display());
            } else {
                print_hex_dump(a.offset, &buf);
            }
            Ok(())
        }
        Command::Write(a) => {
            let data = match (&a.hex, &a.from) {
                (Some(h), _) => parse_hex(h)?,
                (None, Some(p)) => std::fs::read(p)?,
                (None, None) => bail!("pass --hex or --from"),
            };
            let password = a.password.read()?;
            let volume = open_rw(&a.path, password, a.password.pim, a.kind.volume_type())?;
            volume.write_data(a.offset, &data)?;
            volume.flush()?;
            println!("wrote {} bytes at data offset {}", data.len(), a.offset);
            Ok(())
        }
        Command::Format(a) => {
            let kind = match a.fat.as_str() {
                "fat16" => vcrs_mount::FatKind::Fat16,
                "fat32" => vcrs_mount::FatKind::Fat32,
                _ => vcrs_mount::FatKind::Auto,
            };
            let password = a.password.read()?;
            let mut volume = open_rw(&a.path, password, a.password.pim, a.kind.volume_type())?;
            vcrs_mount::format_volume(&mut volume, kind, &a.label)?;
            volume.flush()?;
            println!(
                "created a {kind:?} filesystem (label {:?}) in {}",
                a.label,
                a.path.display()
            );
            println!("mount it with: vcrs mount {} --mount-point Z:", a.path.display());
            Ok(())
        }
        Command::Mount(a) => {
            let options = OpenOptions {
                password: a.password.read()?,
                pim: a.password.pim,
                volume_type: a.kind.volume_type(),
                ..Default::default()
            };

            let disk_mode = match a.disk_mode.as_deref() {
                None => vcrs_mount::DiskMode::default(),
                Some(mode) => vcrs_mount::DiskMode::from_name(mode).with_context(|| {
                    format!("unknown disk mode {mode:?}; expected `partition` or `raw`")
                })?,
            };
            let mut iscsi = vcrs_mount::IscsiMountOptions::for_volume(&a.path);
            iscsi.disk_mode = disk_mode;
            iscsi.read_only = a.read_only;
            iscsi.removable = a.removable;
            if let Some(bind) = &a.bind {
                iscsi.bind_addr = bind.clone();
            }
            if let Some(name) = &a.target_name {
                iscsi.target_name = name.clone();
            }
            vcrs_mount::mount_iscsi(&a.path, &options, &iscsi)?;
            println!("iSCSI target stopped");
            Ok(())
        }
        Command::Dismount(a) => {
            let iqn = a.iscsi.as_deref().context(
                "`vcrs dismount` detaches an iSCSI target: pass `--iscsi <IQN>` \
                 (the target name printed by `vcrs mount`; `iscsicli SessionList 1` lists them)",
            )?;
            iscsi_logout(iqn)?;
            Ok(())
        }
    }
}

/// Detach a target from the Microsoft iSCSI Initiator (needs an elevated prompt).
///
/// The initiator identifies a login by its *session id*, not by the target name,
/// so the session list has to be parsed: `LogoutTarget` only accepts a session
/// id and `QLogoutTarget` does not exist.  A session whose disk Windows is still
/// using cannot be logged out at all ("the session cannot be logged out since a
/// device on that session is currently being used"), so the drive letters are
/// removed and the disk taken offline first.
fn iscsi_logout(iqn: &str) -> Result<()> {
    println!("detaching the iSCSI target {iqn}");
    #[cfg(windows)]
    {
        // 1. release the volume: drop drive letters, then take the disk offline.
        let release = "Get-Disk | Where-Object { $_.FriendlyName -like '*VeraCrypt volume*' } | ForEach-Object { \
             Get-Partition -DiskNumber $_.Number -ErrorAction SilentlyContinue | \
             Where-Object { $_.DriveLetter } | ForEach-Object { \
                 Remove-PartitionAccessPath -DiskNumber $_.DiskNumber -PartitionNumber $_.PartitionNumber \
                     -AccessPath ($_.DriveLetter + ':\') -ErrorAction SilentlyContinue }; \
             Set-Disk -Number $_.Number -IsOffline $true -ErrorAction SilentlyContinue }";
        run_tool("releasing the disk", "powershell", &["-NoProfile", "-Command", release]);

        // 2. log the session out, then 3. forget the static target.
        match std::process::Command::new("iscsicli").arg("SessionList").arg("1").output() {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                match session_id_for_target(&text, iqn) {
                    Some(id) => run_tool(
                        "LogoutTarget",
                        "iscsicli",
                        &["LogoutTarget", id.as_str()],
                    ),
                    None => println!("  no session for {iqn} (already logged out?)"),
                }
            }
            Err(err) => {
                println!("  iscsicli SessionList: {err}");
                println!("  (the Microsoft iSCSI Initiator needs an elevated prompt)");
            }
        }
        run_tool("RemoveTarget", "iscsicli", &["RemoveTarget", iqn]);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = iqn;
        bail!("the iSCSI initiator is only available on Windows")
    }
}

/// Run a helper program and report the outcome without failing the run.
#[cfg(windows)]
fn run_tool(what: &str, program: &str, args: &[&str]) {
    match std::process::Command::new(program).args(args).status() {
        Ok(status) if status.success() => println!("  {what}: ok"),
        Ok(status) => println!("  {what}: exited with {status}"),
        Err(err) => println!("  {what}: {err}"),
    }
}

/// Pick the session id that belongs to `iqn` out of `iscsicli SessionList 1`.
#[cfg(any(windows, test))]
fn session_id_for_target(list: &str, iqn: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in list.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("Session Id") && !value.is_empty() {
                current = Some(value.to_string());
            } else if key.eq_ignore_ascii_case("Target Name") && value == iqn {
                return current;
            }
        }
    }
    None
}

fn open_ro(path: &Path, password: Vec<u8>, pim: i32, volume_type: Option<VolumeType>) -> Result<Volume> {    Volume::open(
        path,
        &OpenOptions {
            password,
            pim,
            volume_type,
            ..Default::default()
        },
    )
    .map_err(Into::into)
}

fn open_rw(path: &Path, password: Vec<u8>, pim: i32, volume_type: Option<VolumeType>) -> Result<Volume> {
    open_ro(path, password, pim, volume_type)
}

fn parse_ea(s: &str) -> Result<EncryptionAlgorithm> {
    EncryptionAlgorithm::from_name(s).with_context(|| {
        let names: Vec<&str> = EncryptionAlgorithm::ALL.iter().map(|e| e.name()).collect();
        format!("unknown encryption algorithm {s:?}; known: {}", names.join(", "))
    })
}

fn parse_prf(s: &str) -> Result<Prf> {
    Prf::from_name(s).with_context(|| {
        let names: Vec<&str> = Prf::ALL.iter().map(|p| p.name()).collect();
        format!("unknown hash algorithm {s:?}; known: {}", names.join(", "))
    })
}

/// Parse `123`, `123K`, `64M`, `4G` (binary suffixes).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some('k' | 'K') => (&s[..s.len() - 1], 1024u64),
        Some('m' | 'M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g' | 'G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some('t' | 'T') => (&s[..s.len() - 1], 1024u64.pow(4)),
        _ => (s, 1),
    };
    let n: u64 = digits.trim().parse().map_err(|e| format!("invalid size {s:?}: {e}"))?;
    n.checked_mul(mult).ok_or_else(|| format!("size {s:?} is too large"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        bail!("hex string must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{e}")))
        .collect()
}

fn print_header(volume: &Volume) {
    let h = &volume.header;
    println!("header:");
    println!("  magic             VERA");
    println!("  version           {}", h.version);
    println!("  required min      0x{:04x}", h.required_min_version);
    println!("  volume type       {:?}", h.volume_type);
    println!("  encryption        {} ({} bytes of key)", h.ea.name(), h.ea.key_size());
    println!("  hash (PRF)        {}", h.prf.name());
    println!("  sector size       {}", h.sector_size);
    println!("  volume data size  {} bytes", h.volume_data_size);
    println!("  enc. area start   {}", h.encrypted_area_start);
    println!("  enc. area length  {}", h.encrypted_area_length);
    println!("  hidden data size  {}", h.hidden_volume_data_size);
    println!("  flags             0x{:08x}", h.flags);
    println!("  creation time     {}", h.creation_time);
    println!("  modification time {}", h.modification_time);
    println!("  salt              {}", hex(&h.salt));
    println!("  master key        {}", hex(&h.master_key));
    println!("layout:");
    println!("  host size         {} bytes", volume.host_size);
    println!("  data offset       {}", volume.data_offset);
    println!("  data size         {} bytes", volume.data_size);
}

fn dump_header_region(args: &HeaderArgs) -> Result<()> {
    let len = std::fs::metadata(&args.path)?.len();
    let layout = VolumeLayout::V2Normal;
    let base = match args.backup {
        true => layout
            .backup_header_offset()
            .map(|o| len.wrapping_add(o as u64))
            .context("layout has no backup header")?,
        false => 0,
    };
    let size = if args.short { VOLUME_HEADER_SIZE_LEGACY } else { VOLUME_HEADER_SIZE };
    let bytes = vcrs_core::volume::read_region(&args.path, base, size as usize)?;
    println!("# {} bytes at offset {base}", bytes.len());
    print_hex_dump(0, &bytes[..VOLUME_HEADER_SIZE_LEGACY as usize]);
    if !args.short {
        println!("--- salt (offset 0, 64 bytes) vs key area (offset {MASTER_KEY_AREA_OFFSET}) ---");
        println!(
            "  encrypted data starts at offset {HEADER_ENCRYPTED_DATA_OFFSET}, {} bytes follow",
            size.saturating_sub(HEADER_ENCRYPTED_DATA_OFFSET as u64)
        );
    }
    Ok(())
}

fn print_hex_dump(base: u64, data: &[u8]) {
    for (row, chunk) in data.chunks(16).enumerate() {
        let addr = base + (row * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let mut ascii = String::new();
        for b in chunk {
            ascii.push(if (0x20..0x7f).contains(b) { *b as char } else { '.' });
        }
        println!("{addr:08x}  {:<47}  {ascii}", hex.join(" "));
    }
}

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::session_id_for_target;

    #[test]
    fn finds_the_session_id_for_a_target() {
        // Trimmed-down `iscsicli SessionList 1` output from a real run.
        let list = "Microsoft iSCSI Initiator Version 10.0 Build 26300\n\
                    Total of 1 sessions\n\
                    Session Id             : ffffe68332afe010-4000013700000006\n\
                    Initiator Node Name    : iqn.1991-05.com.microsoft:desktop-985akhr\n\
                    Target Node Name       : (null)\n\
                    Target Name            : iqn.2025-12.io.vcrs:probe\n\
                    ISID                   : 40 00 01 37 00 00\n";
        assert_eq!(
            session_id_for_target(list, "iqn.2025-12.io.vcrs:probe").as_deref(),
            Some("ffffe68332afe010-4000013700000006")
        );
        assert_eq!(session_id_for_target(list, "iqn.other:target"), None);
        assert_eq!(session_id_for_target("", "iqn.2025-12.io.vcrs:probe"), None);
    }
}
