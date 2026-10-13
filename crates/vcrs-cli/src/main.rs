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
    /// Mount a volume's filesystem at a drive letter (Dokany; needs elevation).
    Mount(MountArgs),
    /// Unmount a drive letter mounted with `vcrs mount`.
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
    /// Drive letter (e.g. `Z:`) or an empty existing directory.
    #[arg(short, long)]
    mount_point: String,
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
    /// Drive letter or mount point directory used by `vcrs mount`.
    mount_point: String,
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
            let mount_options = vcrs_mount::MountOptions {
                read_only: a.read_only,
                ..Default::default()
            };
            println!(
                "mounting {} at {}{} — press Ctrl-C or run `vcrs dismount {}` to stop",
                a.path.display(),
                a.mount_point,
                if a.read_only { " (read-only)" } else { "" },
                a.mount_point
            );
            vcrs_mount::mount(&a.path, &a.mount_point, &options, &mount_options)?;
            println!("{} has been unmounted", a.mount_point);
            Ok(())
        }
        Command::Dismount(a) => {
            vcrs_mount::unmount(&a.mount_point)?;
            println!("unmounted {}", a.mount_point);
            Ok(())
        }
    }
}

fn open_ro(path: &Path, password: Vec<u8>, pim: i32, volume_type: Option<VolumeType>) -> Result<Volume> {
    Volume::open(
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
