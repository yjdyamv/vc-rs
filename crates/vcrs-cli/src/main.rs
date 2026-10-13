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
use vcrs_core::volume::{CreateOptions, OpenOptions, ProtectedRange, RestoreHeaderOptions, Volume};
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
    /// Grow an existing container (VeraCrypt's Volume Expander). The data area
    /// gets bigger and the existing data is kept; the filesystem inside keeps
    /// its old size and has to be extended from the operating system once the
    /// volume is mounted.
    Expand(ExpandArgs),
    /// Encrypt a plaintext partition/device image in place (VeraCrypt's "Encrypt
    /// a non-system partition in place"), or resume an interrupted run: the image
    /// becomes a normal container without needing a second copy of the data.
    EncryptInPlace(EncryptInPlaceArgs),
    /// Permanently decrypt a container that was encrypted in place (VeraCrypt's
    /// "Permanently decrypt a non-system partition/volume"): the data is moved
    /// back down and the file becomes the plaintext image it was made from.
    DecryptInPlace(DecryptInPlaceArgs),
    /// Save a copy of a volume's header area (VeraCrypt's "Backup Volume
    /// Header"), so a damaged header can be restored later without the data
    /// area being needed.
    BackupHeaders(BackupHeadersArgs),
    /// Restore a volume's header (VeraCrypt's "Restore Volume Header"): from a
    /// header backup file, from the copy embedded in the container itself, or
    /// rebuilt from a master key when every header copy is gone.
    RestoreHeaders(RestoreHeadersArgs),
    /// Change a volume's password, keyfiles, PIM and/or header hash (VeraCrypt's
    /// "Change Volume Password"). Only the header is rewritten -- the data area
    /// is not re-encrypted, so it is instant.
    Change(ChangeArgs),
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
    /// Quick format: leave the data area as the host filesystem reports it
    /// instead of writing random-looking data over it. Faster, but the
    /// untouched part of the volume then stays zero bytes on disk, which gives
    /// the container away as a container (VeraCrypt uses a full format by
    /// default for exactly this reason, and refuses a quick format for an outer
    /// volume that is meant to host a hidden volume).
    #[arg(long)]
    quick: bool,
    /// Create the container even when it is larger than the free space on the
    /// filesystem (VeraCrypt refuses that too).
    #[arg(long)]
    no_size_check: bool,
    /// Volume sector size (512, 1024, 2048 or 4096). VeraCrypt defaults to 512
    /// and uses 4096 for very large volumes; the header records it and the
    /// filesystem inside should match it. XTS data-unit numbering is 512-based
    /// regardless, so this changes no ciphertext.
    #[arg(long, default_value_t = 512, value_parser = parse_sector_size)]
    sector_size: u32,
    /// Print the master key of the new volume (it is masked otherwise).
    #[arg(long)]
    show_master_key: bool,
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
    /// Volume sector size, as for `create`.
    #[arg(long, default_value_t = 512, value_parser = parse_sector_size)]
    sector_size: u32,
    /// Print the master key of the new hidden volume (it is masked otherwise).
    #[arg(long)]
    show_master_key: bool,
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
    /// Keyfile, or a directory whose files are used as keyfiles.  Repeatable;
    /// the keyfile pool is mixed into the password exactly like VeraCrypt does.
    #[arg(short = 'k', long = "keyfile", value_name = "PATH", action = clap::ArgAction::Append)]
    keyfiles: Vec<PathBuf>,
}

impl PasswordArgs {
    fn read(&self) -> Result<Vec<u8>> {
        read_password(
            self.password.as_deref(),
            self.password_stdin,
            "no password given (use --password, $VCRS_PASSWORD or --password-stdin)",
        )
    }

    /// True when a credential was supplied, so a volume can be opened without
    /// having to ask.
    fn is_given(&self) -> bool {
        self.password.is_some() || self.password_stdin || !self.keyfiles.is_empty()
    }
    fn open_options(&self, volume_type: Option<VolumeType>, use_backup_header: bool) -> Result<OpenOptions> {
        Ok(OpenOptions {
            password: self.read()?,
            keyfiles: self.keyfiles.clone(),
            pim: self.pim,
            volume_type,
            use_backup_header,
            ..Default::default()
        })
    }
}

/// Read a password the way every command does: raw bytes from stdin (with one
/// trailing newline trimmed) or the UTF-8 bytes of the string that was given.
fn read_password(value: Option<&str>, from_stdin: bool, missing: &str) -> Result<Vec<u8>> {
    if from_stdin {
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
    match value {
        Some(password) => Ok(password.as_bytes().to_vec()),
        None => bail!("{missing}"),
    }
}

/// The credentials to put into a header, for `vcrs change`. VeraCrypt's
/// change-password dialog asks for the same fields.
#[derive(Args, Clone)]
struct NewPasswordArgs {
    /// New password.
    #[arg(long = "new-password", env = "VCRS_NEW_PASSWORD", hide_env_values = true)]
    new_password: Option<String>,
    /// Read the new password from stdin (raw bytes, one trailing newline trimmed).
    #[arg(long = "new-password-stdin", conflicts_with = "new_password")]
    new_password_stdin: bool,
    /// New keyfile (repeatable); replaces the volume's current keyfiles.
    #[arg(long = "new-keyfile", value_name = "PATH", action = clap::ArgAction::Append)]
    new_keyfiles: Vec<PathBuf>,
    /// New PIM. Defaults to the PIM the volume is opened with, so that changing
    /// only the password cannot silently weaken the key derivation.
    #[arg(long = "new-pim", value_name = "N")]
    new_pim: Option<i32>,
    /// New header hash algorithm; defaults to the one the volume already uses.
    #[arg(long = "new-hash", value_name = "PRF")]
    new_prf: Option<String>,
}

impl NewPasswordArgs {
    fn read(&self) -> Result<Vec<u8>> {
        read_password(
            self.new_password.as_deref(),
            self.new_password_stdin,
            "no new password given (use --new-password, $VCRS_NEW_PASSWORD or \
             --new-password-stdin)",
        )
    }

    /// The password bytes the KDF sees, i.e. with the keyfile pool mixed in.
    fn effective_password(&self, volume: &Path) -> Result<Vec<u8>> {
        Ok(vcrs_core::apply_keyfiles(
            &self.read()?,
            &self.new_keyfiles,
            Some(volume),
        )?)
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
    #[command(flatten)]
    protect: HiddenProtectionArgs,
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
    #[command(flatten)]
    protect: HiddenProtectionArgs,
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

#[derive(Args)]
struct ExpandArgs {
    /// Container to grow.
    path: PathBuf,
    /// New size of the container, e.g. `200M`, `2G` (must be larger than the
    /// current size).
    #[arg(short, long, value_parser = parse_size)]
    size: u64,
    /// Confirm the expansion even though any hidden volume inside the container
    /// is destroyed by it (VeraCrypt asks the same question interactively).
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct EncryptInPlaceArgs {
    /// Image file to encrypt in place: a plain (unencrypted) file/partition image
    /// whose last 128 KiB are free (VeraCrypt shrinks the filesystem by that much
    /// first; a partition image usually needs `truncate -s -128K` or zeroed
    /// trailing bytes). If the file already contains a container whose in-place
    /// encryption was interrupted, the run resumes instead.
    path: PathBuf,
    /// Encryption algorithm for the new volume.
    #[arg(long, default_value = "AES")]
    ea: String,
    /// Header key derivation function for the new volume.
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    #[command(flatten)]
    password: PasswordArgs,
}

#[derive(Args)]
struct DecryptInPlaceArgs {
    /// Container made by `vcrs encrypt-in-place` (or by VeraCrypt's in-place
    /// encryption). It must hold a *completed* in-place volume; the run moves the
    /// data back down and truncates the file to the plaintext image it was made
    /// from.
    path: PathBuf,
    /// Continue an interrupted in-place *decryption*. Without it a run only starts
    /// from a completed in-place volume, because a half decrypted and a half
    /// encrypted container look identical in the header (VeraCrypt tells them apart
    /// by the switch too: `/resumeinplacedec` vs `/zinplace`).
    #[arg(long)]
    resume: bool,
    #[command(flatten)]
    password: PasswordArgs,
}

/// Saves a header backup.
#[derive(Args)]
struct BackupHeadersArgs {
    /// Volume file whose header area is saved.
    path: PathBuf,
    /// Where to write the backup (default: `<volume>.hc`).
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Restores a header from one of the three sources.
#[derive(Args)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["from", "embedded", "master_key"]))]
struct RestoreHeadersArgs {
    /// Volume file whose header is restored.
    path: PathBuf,
    /// Restore from a header backup written by `vcrs backup-headers`.
    #[arg(long, value_name = "FILE")]
    from: Option<PathBuf>,
    /// Restore from the backup header embedded in the container itself (the
    /// copy at the end of the file), without needing a backup file.
    #[arg(long)]
    embedded: bool,
    /// Rebuild the header from the volume's master key, in hex, for when every
    /// header copy is lost. The data area itself is untouched.
    #[arg(long, value_name = "HEX")]
    master_key: Option<String>,
    /// Size of the volume's data area when rebuilding from a master key. An
    /// ordinary volume's data area is `container size - 262144` and is computed
    /// automatically; a hidden volume's has to be given here.
    #[arg(long, value_name = "SIZE", value_parser = parse_size, requires = "master_key")]
    data_size: Option<u64>,
    /// Encryption algorithm the master key belongs to.
    #[arg(long, default_value = "AES")]
    ea: String,
    /// Header hash algorithm for the rebuilt header.
    #[arg(long, default_value = "SHA-512")]
    prf: String,
    /// Sector size the volume was created with.
    #[arg(long, default_value_t = 512)]
    sector_size: u32,
    /// Which header to restore: the hidden volume's instead of the outer one.
    #[command(flatten)]
    kind: VolumeKindArgs,
    /// The volume's password (or, when rebuilding from a master key, the
    /// password the rebuilt header should use). Without one the restored header
    /// is written but not verified.
    #[command(flatten)]
    password: PasswordArgs,
}

/// `vcrs change` arguments.
#[derive(Args)]
struct ChangeArgs {
    /// Volume whose header is rewritten.
    path: PathBuf,
    /// Open the volume's *backup* header first (for a volume whose primary
    /// header is damaged).
    #[arg(long)]
    backup: bool,
    /// Which volume to change: the hidden volume's header instead of the outer
    /// one.
    #[command(flatten)]
    kind: VolumeKindArgs,
    /// The volume's current credentials.
    #[command(flatten)]
    password: PasswordArgs,
    /// The credentials to put into the header.
    #[command(flatten)]
    new: NewPasswordArgs,
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

/// VeraCrypt's *protect hidden volume* option: while the outer volume is in use,
/// any write that would land inside the hidden volume fails instead of
/// destroying it. Needs the hidden volume's own credentials.
#[derive(Args, Clone)]
struct HiddenProtectionArgs {
    /// Protect the hidden volume inside this outer volume from being written to.
    #[arg(long)]
    protect_hidden: bool,
    /// Password of the hidden volume.
    #[arg(long = "hidden-password", env = "VCRS_HIDDEN_PASSWORD", hide_env_values = true)]
    hidden_password: Option<String>,
    /// Read the hidden volume's password from stdin (raw bytes).
    #[arg(long = "hidden-password-stdin", conflicts_with = "hidden_password")]
    hidden_password_stdin: bool,
    /// PIM of the hidden volume.
    #[arg(long = "hidden-pim", default_value_t = 0)]
    hidden_pim: i32,
    /// Keyfile of the hidden volume (repeatable).
    #[arg(long = "hidden-keyfile", value_name = "PATH", action = clap::ArgAction::Append)]
    hidden_keyfiles: Vec<PathBuf>,
}

impl HiddenProtectionArgs {
    /// How to open the hidden volume, or `None` when protection is off.
    fn hidden_open_options(&self) -> Result<Option<OpenOptions>> {
        if !self.protect_hidden {
            if self.hidden_password.is_some()
                || self.hidden_password_stdin
                || !self.hidden_keyfiles.is_empty()
            {
                bail!("--hidden-password/--hidden-pim/--hidden-keyfile need --protect-hidden");
            }
            return Ok(None);
        }
        let creds = PasswordArgs {
            password: self.hidden_password.clone(),
            password_stdin: self.hidden_password_stdin,
            pim: self.hidden_pim,
            keyfiles: self.hidden_keyfiles.clone(),
        };
        let options = creds.open_options(Some(VolumeType::Hidden), false).context(
            "--protect-hidden needs the hidden volume's password \
             (--hidden-password, $VCRS_HIDDEN_PASSWORD or --hidden-password-stdin)",
        )?;
        Ok(Some(options))
    }
}

/// Turn on hidden-volume protection for an already opened outer volume.
fn apply_hidden_protection(
    volume: &Volume,
    protect: &HiddenProtectionArgs,
    path: &Path,
) -> Result<()> {
    let Some(hidden_options) = protect.hidden_open_options()? else {
        return Ok(());
    };
    let hidden = Volume::open(path, &hidden_options).with_context(|| {
        format!(
            "opening the hidden volume of {} (needed by --protect-hidden)",
            path.display()
        )
    })?;
    let range = ProtectedRange::new(hidden.data_offset, hidden.data_size);
    println!(
        "protecting the hidden volume: host range {}..{} ({} bytes) is now write-protected",
        range.start,
        range.end(),
        range.length
    );
    volume.protect_hidden_volume(range);
    Ok(())
}

#[derive(Args)]
struct InfoArgs {
    path: PathBuf,
    /// Open the backup header (at the end of the file) instead of the primary one.
    #[arg(long)]
    backup: bool,
    /// Print the master key (masked by default: it decrypts the data area without
    /// the password).
    #[arg(long)]
    show_master_key: bool,
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
    #[command(flatten)]
    protect: HiddenProtectionArgs,
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
            if !a.no_size_check {
                check_free_space(&a.path, a.size)?;
            }
            if a.quick {
                eprintln!(
                    "warning: --quick leaves the unused part of the data area empty on disk (zero \
                     bytes on\n  NTFS/ext4), so it is recognisable as a region nobody wrote to. \
                     VeraCrypt uses a\n  full format by default for that reason, and refuses quick \
                     formats for an outer volume\n  that is meant to host a hidden volume."
                );
            }
            let options = CreateOptions {
                ea,
                prf,
                password: a.password.read()?,
                keyfiles: a.password.keyfiles.clone(),
                pim: a.password.pim,
                sector_size: a.sector_size,
                full_format: !a.quick,
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
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::CreateHidden(a) => {
            if vcrs_core::looks_quick_formatted(&a.path)? {
                eprintln!(
                    "warning: {} looks like it was created with a quick format (its unused space is\n  \
                     still zero bytes on disk), so a hidden volume inside it can be detected. \
                     VeraCrypt\n  refuses to put a hidden volume into a quickly formatted outer \
                     volume.",
                    a.path.display()
                );
            }
            let options = CreateOptions {
                ea: parse_ea(&a.ea)?,
                prf: parse_prf(&a.prf)?,
                password: a.password.read()?,
                keyfiles: a.password.keyfiles.clone(),
                pim: a.password.pim,
                sector_size: a.sector_size,
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
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::Info(a) => {
            let options = a.password.open_options(a.kind.volume_type(), a.backup)?;
            let volume = Volume::open(&a.path, &options)?;
            print_header(&volume, a.show_master_key);
            Ok(())
        }
        Command::Header(a) => dump_header_region(&a),
        Command::Read(a) => {
            let volume = open_ro(&a.path, &a.password, a.kind.volume_type())?;
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
            let volume = open_rw(&a.path, &a.password, a.kind.volume_type())?;
            apply_hidden_protection(&volume, &a.protect, &a.path)?;
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
            let mut volume = open_rw(&a.path, &a.password, a.kind.volume_type())?;
            apply_hidden_protection(&volume, &a.protect, &a.path)?;
            vcrs_mount::format_volume(&mut volume, kind, &a.label)?;
            volume.flush()?;
            println!(
                "created a {kind:?} filesystem (label {:?}) in {}",
                a.label,
                a.path.display()
            );
            println!("expose it to Windows with: vcrs mount {}", a.path.display());
            Ok(())
        }
        Command::Expand(a) => {
            if !a.force {
                bail!(
                    "expanding a container destroys any hidden volume inside it (VeraCrypt asks \
                     the same question interactively); pass --force if you are sure that {} has \
                     no hidden volume",
                    a.path.display()
                );
            }
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let mut volume = Volume::open(&a.path, &options)?;
            let old_host_size = volume.host_size;
            let old_data_size = volume.data_size;
            let started = std::time::Instant::now();
            volume.expand(a.size, &password, a.password.pim)?;
            volume.flush()?;
            println!(
                "expanded {} from {old_host_size} to {} bytes in {:.2}s",
                a.path.display(),
                volume.host_size,
                started.elapsed().as_secs_f64()
            );
            println!(
                "  data area: {} -> {} bytes (the master key and the existing data are unchanged)",
                old_data_size, volume.data_size
            );
            println!(
                "  the filesystem inside still has its old size: mount the volume and extend it \
                 there (Windows: Disk Management -> Extend Volume, or `Resize-Partition`)"
            );
            Ok(())
        }
        Command::EncryptInPlace(a) => {
            let ea = EncryptionAlgorithm::from_name(&a.ea)
                .with_context(|| format!("unknown encryption algorithm {:?}", a.ea))?;
            let prf = Prf::from_name(&a.prf)
                .with_context(|| format!("unknown PRF {:?}", a.prf))?;
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let host_size = std::fs::metadata(&a.path)
                .with_context(|| format!("reading {}", a.path.display()))?
                .len();
            let started = std::time::Instant::now();
            let volume =
                vcrs_core::encrypt_in_place(&a.path, &password, a.password.pim, ea, prf)?;
            let elapsed = started.elapsed();
            match volume.in_place() {
                Some(state) => {
                    println!(
                        "paused: {} of {} bytes encrypted ({:.1}%) in {:.1}s",
                        state.encrypted_length,
                        state.total(),
                        state.progress() * 100.0,
                        elapsed.as_secs_f64()
                    );
                    println!(
                        "  run the same command again to continue (it resumes from the backup \
                         header)"
                    );
                }
                None => {
                    println!(
                        "encrypted {} in place in {:.1}s (was {host_size} bytes)",
                        a.path.display(),
                        elapsed.as_secs_f64()
                    );
                    println!(
                        "  {}: {} byte data area, mountable like any other container",
                        volume.header.ea,
                        volume.data_size
                    );
                }
            }
            Ok(())
        }
        Command::DecryptInPlace(a) => {
            // Build the options once: `--password-stdin` can only be read once.
            let options = a.password.open_options(None, false)?;
            let password = options.effective_password(Some(&a.path))?;
            let started = std::time::Instant::now();
            let outcome =
                vcrs_core::decrypt_in_place_stopping_after(
                    &a.path,
                    &password,
                    a.password.pim,
                    a.resume,
                    None,
                )?;
            let elapsed = started.elapsed();
            if outcome.finished {
                println!(
                    "decrypted {} in place in {:.1}s",
                    a.path.display(),
                    elapsed.as_secs_f64()
                );
                println!(
                    "  the file is a {} byte plaintext image again (the filesystem followed by \
                     {} zero bytes)",
                    outcome.data_size + 131072,
                    131072
                );
            } else {
                let left = outcome.data_size - outcome.decrypted;
                println!(
                    "paused: {} of {} bytes decrypted ({:.1}%) in {:.1}s",
                    outcome.decrypted,
                    outcome.data_size,
                    outcome.decrypted as f64 * 100.0 / outcome.data_size.max(1) as f64,
                    elapsed.as_secs_f64()
                );
                println!(
                    "  {left} bytes are still encrypted; continue with \
                     `vcrs decrypt-in-place --resume`"
                );
            }
            Ok(())
        }
        Command::BackupHeaders(a) => {
            let out = a
                .out
                .clone()
                .unwrap_or_else(|| default_header_backup_path(&a.path));
            let written = vcrs_core::backup_headers(&a.path, &out)?;
            println!("wrote a {written} byte header backup to {}", out.display());
            println!(
                "  keep it away from the container: with this file and the password, a container \
                 whose\n  headers were destroyed can be restored without touching the data area"
            );
            Ok(())
        }
        Command::RestoreHeaders(a) => restore_headers(&a),
        Command::Change(a) => {
            let options = a.password.open_options(a.kind.volume_type(), a.backup)?;
            let mut volume = Volume::open(&a.path, &options)?;
            let new_password = a.new.effective_password(&a.path)?;
            // A PIM is not stored in the header, so "no --new-pim" means "keep
            // using the PIM this volume was opened with" rather than silently
            // dropping back to the default iteration count.
            let new_pim = a.new.new_pim.unwrap_or(a.password.pim);
            let new_prf = match &a.new.new_prf {
                Some(name) => Some(parse_prf(name)?),
                None => None,
            };
            let old_prf = volume.header.prf;
            volume.change_credentials(&new_password, new_pim, new_prf)?;
            println!(
                "changed the {} header of {}: hash {} -> {}, PIM {} -> {}",
                if a.kind.hidden { "hidden" } else { "ordinary" },
                a.path.display(),
                old_prf,
                volume.header.prf,
                a.password.pim,
                new_pim
            );
            println!("  the data area was not touched (the master key is unchanged)");
            print_header(&volume, false);
            Ok(())
        }
        Command::Mount(a) => {
            let options = a.password.open_options(a.kind.volume_type(), false)?;

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
            iscsi.protect_hidden = a.protect.hidden_open_options()?;
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

fn open_ro(path: &Path, creds: &PasswordArgs, volume_type: Option<VolumeType>) -> Result<Volume> {
    Volume::open(path, &creds.open_options(volume_type, false)?).map_err(Into::into)
}

fn open_rw(path: &Path, creds: &PasswordArgs, volume_type: Option<VolumeType>) -> Result<Volume> {
    open_ro(path, creds, volume_type)
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

/// Parse a volume sector size: VeraCrypt allows 512..4096 in 512-byte steps
/// (`TC_MIN_VOLUME_SECTOR_SIZE`..`TC_MAX_VOLUME_SECTOR_SIZE`).
fn parse_sector_size(s: &str) -> Result<u32, String> {
    let value: u32 = s
        .trim()
        .parse()
        .map_err(|_| format!("{s:?} is not a sector size"))?;
    if !(512..=4096).contains(&value) || value % 512 != 0 {
        return Err(format!(
            "sector size must be 512..4096 and a multiple of 512, got {value}"
        ));
    }
    Ok(value)
}

/// Parse `123`, `123K`, `64M`, `4G` (binary suffixes).
fn parse_size(s: &str) -> Result<u64, String> {    let s = s.trim();
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

fn print_header(volume: &Volume, show_master_key: bool) {
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
    println!("  master key        {}", format_master_key(show_master_key, &h.master_key));
    println!("layout:");
    println!("  host size         {} bytes", volume.host_size);
    println!("  data offset       {}", volume.data_offset);
    println!("  data size         {} bytes", volume.data_size);
}

/// The master key is the one secret that decrypts the data area without the
/// password (that is why VeraCrypt's rescue disk stores it), so it stays hidden
/// unless the caller explicitly asks for it. VeraCrypt's format wizard does the
/// same thing: the fields show stars until "Display keys" is ticked.
fn format_master_key(show: bool, master_key: &[u8]) -> String {
    if show {
        hex(master_key)
    } else {
        format!("<{} bytes, pass --show-master-key to print>", master_key.len())
    }
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

/// Default name for a header backup: `<volume>.hc`.
fn default_header_backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".hc");
    PathBuf::from(name)
}

/// `vcrs restore-headers`: put a header back from a backup file, from the
/// container's own embedded copy, or -- when every copy is gone -- from a
/// master key.
fn restore_headers(a: &RestoreHeadersArgs) -> Result<()> {
    let volume_type = a.kind.volume_type().unwrap_or(VolumeType::Normal);

    if let Some(key) = &a.master_key {
        let master_key = parse_hex(key)?;
        let host_size = std::fs::metadata(&a.path)
            .with_context(|| format!("reading {}", a.path.display()))?
            .len();
        let data_size = match (a.data_size, volume_type) {
            (Some(size), _) => size,
            (None, VolumeType::Normal) => VolumeLayout::V2Normal
                .max_data_size(host_size)
                .with_context(|| {
                    format!("{} is too small to hold a volume", a.path.display())
                })?,
            (None, VolumeType::Hidden) => bail!(
                "rebuilding a hidden volume's header needs --data-size: its data area does not sit \
                 where an ordinary volume's would"
            ),
        };
        let options = RestoreHeaderOptions {
            password: a.password.read()?,
            keyfiles: a.password.keyfiles.clone(),
            pim: a.password.pim,
            ea: parse_ea(&a.ea)?,
            prf: parse_prf(&a.prf)?,
            sector_size: a.sector_size,
            volume_type,
            data_size,
        };
        let volume = vcrs_core::restore_headers_from_master_key(&a.path, &master_key, &options)?;
        println!(
            "rebuilt the {} header of {} from its master key",
            volume_name(volume_type),
            a.path.display()
        );
        print_header(&volume, false);
        return Ok(());
    }

    // Writing a header does not need a password, but without one the result
    // cannot be checked -- and a backup taken from another volume would leave
    // this container unopenable.
    let verify = if a.password.is_given() {
        Some(a.password.open_options(a.kind.volume_type(), false)?)
    } else {
        None
    };
    let volume = if let Some(from) = &a.from {
        vcrs_core::restore_headers(&a.path, from, volume_type, verify.as_ref())?
    } else if a.embedded {
        vcrs_core::restore_headers_from_embedded(&a.path, volume_type, verify.as_ref())?
    } else {
        bail!("pass --from <FILE>, --embedded or --master-key <HEX>")
    };

    match volume {
        Some(volume) => {
            println!(
                "restored the {} header of {} and opened it with the password given",
                volume_name(volume_type),
                a.path.display()
            );
            print_header(&volume, false);
        }
        None => {
            println!(
                "restored the {} header of {}",
                volume_name(volume_type),
                a.path.display()
            );
            eprintln!(
                "warning: no password was given, so the restored header was not checked; if it came\n  \
                 from another volume, this container can no longer be opened"
            );
        }
    }
    Ok(())
}

fn volume_name(volume_type: VolumeType) -> &'static str {
    match volume_type {
        VolumeType::Normal => "ordinary",
        VolumeType::Hidden => "hidden",
    }
}

/// Refuse to create a container larger than the free space on the filesystem it
/// is created on (VeraCrypt's "not enough free space" check), unless
/// `--no-size-check` was passed.
fn check_free_space(path: &Path, host_size: u64) -> Result<()> {
    let Some(free) = available_space(path) else {
        return Ok(());
    };
    if host_size > free {
        bail!(
            "the container ({}) does not fit in the {} free on {}: pass --no-size-check to create \
             it anyway (the format would then fail part-way through)",
            human_size(host_size),
            human_size(free),
            existing_dir(path).display()
        );
    }
    Ok(())
}

/// The closest existing directory, i.e. the filesystem the container will live
/// on.
fn existing_dir(path: &Path) -> PathBuf {
    let mut candidate = path.parent().map(Path::to_path_buf);
    while let Some(dir) = candidate {
        if dir.as_os_str().is_empty() {
            break;
        }
        if dir.is_dir() {
            return dir;
        }
        candidate = dir.parent().map(Path::to_path_buf);
    }
    PathBuf::from(".")
}

/// Bytes available to the user on the filesystem that holds `path`.
#[cfg(windows)]
fn available_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::um::winnt::ULARGE_INTEGER;

    let dir = existing_dir(path);
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut free: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` is a NUL-terminated UTF-16 path and `free` is a valid,
    // initialised ULARGE_INTEGER of ours.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        None
    } else {
        // SAFETY: the call succeeded, so the union holds the free byte count.
        Some(unsafe { *free.QuadPart() })
    }
}

/// Bytes available to the user on the filesystem that holds `path`.
#[cfg(unix)]
fn available_space(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;

    let dir = existing_dir(path);
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated C string and `stat` is ours.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(any(windows, unix)))]
fn available_space(_path: &Path) -> Option<u64> {
    None
}

/// A byte count as `12.34 MiB`, for messages a person reads.
fn human_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, factor) in UNITS {
        if bytes >= factor {
            return format!("{:.2} {unit}", bytes as f64 / factor as f64);
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::{format_master_key, human_size, parse_sector_size, session_id_for_target};

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

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(20 * 1024 * 1024), "20.00 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn the_master_key_is_masked_unless_requested() {
        let key = [0xab, 0xcd];
        assert_eq!(format_master_key(true, &key), "abcd");
        let hidden = format_master_key(false, &key);
        assert!(!hidden.contains("abcd"), "the key must not appear: {hidden}");
        assert!(hidden.contains("2 bytes") && hidden.contains("--show-master-key"));
    }

    #[test]
    fn sector_sizes_are_validated_like_veracrypt_does() {
        for good in ["512", "1024", "2048", "4096", " 4096 "] {
            assert!(parse_sector_size(good).is_ok(), "{good} should be accepted");
        }
        for bad in ["0", "256", "600", "4097", "8192", "abc", ""] {
            let err = parse_sector_size(bad).expect_err("{bad} should be refused");
            assert!(!err.is_empty());
        }
    }
}
