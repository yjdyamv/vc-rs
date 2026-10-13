//! The Dokany file system handler that exposes the FAT filesystem living inside
//! a VeraCrypt-compatible volume.
//!
//! Dokany calls the methods of [`FileSystemHandler`] on the `Dokan` file system
//! thread(s) while the volume is mounted. The FAT filesystem itself is shared
//! through a `Mutex`, so all operations are serialised; `fatfs::File` borrows the
//! filesystem and therefore cannot be kept in the per-file [`FileContext`] —
//! instead every operation reopens the file by path.

use std::{
    cmp::Ordering,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dokan::{
    CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler, FileSystemMounter, FileTimeOperation,
    FillDataError, FillDataResult, FindData, MountFlags, OperationInfo, OperationResult, VolumeInfo,
    IO_SECURITY_CONTEXT,
};
use dokan_sys::win32::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_MAXIMUM_DISPOSITION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
};
use fatfs::{FatType, FileSystem, FsOptions};
use vcrs_core::{
    error::{Error, Result},
    volume::{OpenOptions, Volume},
};
use widestring::U16CString;
use winapi::{
    shared::{ntdef::NTSTATUS, ntstatus::*},
    um::winnt::{
        ACCESS_MASK, FILE_APPEND_DATA, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_CASE_PRESERVED_NAMES,
        FILE_READ_ONLY_VOLUME, FILE_UNICODE_ON_DISK,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, GENERIC_WRITE,
    },
};

use crate::{
    device::{VolumeDevice, SECTOR_SIZE},
    MountOptions,
};

/// `FILE_REMOVABLE_MEDIA` from `winnt.h`. `winapi` does not export it.
const FILE_REMOVABLE_MEDIA: u32 = 0x0000_0001;

/// Longest component a FAT file system can hold (255 UTF-16 code units).
const MAX_COMPONENT_LENGTH: u32 = 255;

/// The attributes Windows tracks for a file.
const TRACKED_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_ARCHIVE;

/// The FAT filesystem over the volume data area, as `fatfs` sees it.
type FatFs = FileSystem<VolumeDevice<Volume>>;

/// Makes the `fatfs` filesystem usable from Dokany's threads.
///
/// `fatfs::FileSystem` is neither `Send` nor `Sync`, because `FsOptions` stores
/// `&'static dyn OemCpConverter` and `&'static dyn TimeProvider` trait objects,
/// and neither trait has a `Sync` bound (fatfs 0.3.6, `fs.rs:735` and
/// `time.rs:127`). Dokany on the other hand requires its handler to be `Sync`.
///
/// This is the only `unsafe` code in the crate:
///
/// * the wrapped filesystem is only ever reachable through the `Mutex` in
///   [`VolumeFsHandler`], so two threads can never touch it at the same time,
/// * the two trait objects are references to stateless unit structs
///   (`LossyOemCpConverter`, `DefaultTimeProvider`) whose methods only read
///   process-wide state, and
/// * the `fatfs::File`/`fatfs::Dir` values borrowed from it are created and
///   dropped within a single locked operation.
struct SharedFs(FatFs);

// SAFETY: see the documentation of `SharedFs`.
unsafe impl Send for SharedFs {}
// SAFETY: see the documentation of `SharedFs`.
unsafe impl Sync for SharedFs {}

impl std::ops::Deref for SharedFs {
    type Target = FatFs;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Per-file state Dokany keeps while a file or directory is open.
///
/// `fatfs::File` borrows the filesystem, so it cannot be stored here; the path
/// is kept instead and the file is reopened for every operation. FAT has no
/// stable file identifiers either, which is why the same trick is used for
/// attributes and file information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContext {
    /// Path relative to the volume root, with `\` separators and without a
    /// leading or trailing separator (`""` is the volume root).
    pub path: String,
    /// `true` if the opened entry is a directory.
    pub is_dir: bool,
    /// The Windows attributes the entry had when it was opened.
    pub attributes: u32,
    /// `FILE_DELETE_ON_CLOSE` was requested at create time.
    pub delete_on_close: bool,
}

/// A snapshot of a FAT directory entry.
///
/// `fatfs` only exposes attributes and timestamps through `DirEntry`, which
/// borrows the directory iterator, so the values needed by Dokany's parameter
/// structs are copied out into this owned type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryInfo {
    attributes: u32,
    file_size: u64,
    is_dir: bool,
    creation_time: SystemTime,
    last_access_time: SystemTime,
    last_write_time: SystemTime,
}

impl EntryInfo {
    /// What the volume root looks like: always a directory, no timestamps.
    fn root() -> Self {
        EntryInfo {
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            file_size: 0,
            is_dir: true,
            creation_time: UNIX_EPOCH,
            last_access_time: UNIX_EPOCH,
            last_write_time: UNIX_EPOCH,
        }
    }
}

/// The Dokany handler serving one mounted volume.
pub struct VolumeFsHandler {
    /// The FAT filesystem over the decrypted volume data area.
    filesystem: Mutex<SharedFs>,
    /// A second handle to the same device, used to flush the sector cache
    /// without going through `fatfs`.
    device: VolumeDevice<Volume>,
    read_only: bool,
    removable: bool,
    label: String,
    fat_name: &'static str,
    cluster_size: u32,
    volume_id: u32,
}

impl VolumeFsHandler {
    /// Create a handler for an already opened FAT filesystem.
    ///
    /// `device` must be a handle to the same [`VolumeDevice`] the filesystem was
    /// created from (it is used to push cached sectors into the volume).
    pub fn new(filesystem: FatFs, device: VolumeDevice<Volume>, options: &MountOptions) -> Self {
        let label = filesystem.volume_label().trim_end().to_string();
        let fat_name = match filesystem.fat_type() {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        };
        let cluster_size = filesystem.cluster_size();
        let volume_id = filesystem.volume_id();
        VolumeFsHandler {
            cluster_size,
            volume_id,
            filesystem: Mutex::new(SharedFs(filesystem)),
            device,
            read_only: options.read_only,
            removable: options.removable,
            label,
            fat_name,
        }
    }

    /// The volume label reported to Windows.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The FAT flavour (`FAT12`, `FAT16` or `FAT32`).
    pub fn fat_name(&self) -> &'static str {
        self.fat_name
    }

    /// The cluster size the filesystem was formatted with.
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// `true` if the volume was mounted read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn lock(&self) -> MutexGuard<'_, SharedFs> {
        // A panic in one operation must not make the whole mounted volume
        // unusable, so a poisoned mutex is recovered.
        self.filesystem.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Push the cached sectors into the volume file (no `fsync`).
    fn write_back(&self) -> OperationResult<()> {
        self.device.write_back().map_err(|error| {
            log::error!("could not write the volume data area back: {error}");
            STATUS_UNEXPECTED_IO_ERROR
        })
    }

    /// Look up `path` (`""` for the volume root) and snapshot its entry.
    fn lookup(&self, path: &str) -> OperationResult<Option<EntryInfo>> {
        lookup(&self.lock(), path)
    }
}

/// Reject a write on a read-only mount.
fn reject_if_read_only(read_only: bool) -> OperationResult<()> {
    if read_only {
        Err(STATUS_MEDIA_WRITE_PROTECTED)
    } else {
        Ok(())
    }
}

/// Maps `fatfs`/`io` errors onto NTSTATUS values Windows understands.
///
/// Most of `fatfs`'s errors are `io::ErrorKind::Other` with a descriptive
/// message, so the classification falls back to matching the message.
fn fatfs_error(error: std::io::Error) -> NTSTATUS {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        ErrorKind::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        ErrorKind::PermissionDenied => STATUS_ACCESS_DENIED,
        ErrorKind::InvalidInput => STATUS_INVALID_PARAMETER,
        ErrorKind::UnexpectedEof => STATUS_END_OF_FILE,
        _ => {
            let message = error.to_string().to_ascii_lowercase();
            if message.contains("not a directory") {
                STATUS_NOT_A_DIRECTORY
            } else if message.contains("is a directory") {
                STATUS_FILE_IS_A_DIRECTORY
            } else if message.contains("not empty") {
                STATUS_DIRECTORY_NOT_EMPTY
            } else if message.contains("full") || message.contains("no space") {
                STATUS_DISK_FULL
            } else if message.contains("invalid") || message.contains("too small") {
                STATUS_INVALID_PARAMETER
            } else {
                log::error!("fatfs error: {error}");
                STATUS_UNEXPECTED_IO_ERROR
            }
        }
    }
}

fn io_error(error: std::io::Error) -> NTSTATUS {
    fatfs_error(error)
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// Normalise a Dokany file name to a volume-relative path with `\` separators,
/// no leading/trailing separator and no empty components. `""` is the root.
fn relative_path(path: &str) -> String {
    let mut normalised = String::with_capacity(path.len());
    for component in path.split(['\\', '/']) {
        if component.is_empty() {
            continue;
        }
        if !normalised.is_empty() {
            normalised.push('\\');
        }
        normalised.push_str(component);
    }
    normalised
}

/// Split a volume-relative path into `(parent, last component)`.
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('\\') {
        Some(index) => (&path[..index], &path[index + 1..]),
        None => ("", path),
    }
}

/// The form `fatfs` expects: relative to the root directory, `/` separated.
fn fatfs_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.replace('\\', "/")
    }
}

/// Open `path` (`""` is the root) as a directory.
fn open_directory<'a>(filesystem: &'a FatFs, path: &str) -> OperationResult<fatfs::Dir<'a, VolumeDevice<Volume>>> {
    let root = filesystem.root_dir();
    if path.is_empty() {
        Ok(root)
    } else {
        root.open_dir(&fatfs_path(path)).map_err(fatfs_error)
    }
}

/// Open `path` as a file.
fn open_file<'a>(filesystem: &'a FatFs, path: &str) -> OperationResult<fatfs::File<'a, VolumeDevice<Volume>>> {
    let root = filesystem.root_dir();
    root.open_file(&fatfs_path(path)).map_err(fatfs_error)
}

/// Look up `path` and snapshot its directory entry.
fn lookup(filesystem: &FatFs, path: &str) -> OperationResult<Option<EntryInfo>> {
    if path.is_empty() {
        return Ok(Some(EntryInfo::root()));
    }
    let (parent, name) = split_path(path);
    let directory = open_directory(filesystem, parent)?;
    for entry in directory.iter() {
        let entry = entry.map_err(fatfs_error)?;
        if entry.file_name().eq_ignore_ascii_case(name) {
            return Ok(Some(entry_info(&entry)));
        }
    }
    Ok(None)
}

/// `true` if `path` is a directory without entries other than `.` and `..`.
fn directory_is_empty(filesystem: &FatFs, path: &str) -> OperationResult<bool> {
    let directory = open_directory(filesystem, path)?;
    for entry in directory.iter() {
        let entry = entry.map_err(fatfs_error)?;
        let name = entry.file_name();
        if name != "." && name != ".." {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Windows attributes of a FAT directory entry (they map 1:1).
fn entry_attributes(entry: &fatfs::DirEntry<'_, VolumeDevice<Volume>>) -> u32 {
    let attributes = entry.attributes();
    let mut windows = 0;
    if attributes.contains(fatfs::FileAttributes::READ_ONLY) {
        windows |= FILE_ATTRIBUTE_READONLY;
    }
    if attributes.contains(fatfs::FileAttributes::HIDDEN) {
        windows |= FILE_ATTRIBUTE_HIDDEN;
    }
    if attributes.contains(fatfs::FileAttributes::SYSTEM) {
        windows |= FILE_ATTRIBUTE_SYSTEM;
    }
    if attributes.contains(fatfs::FileAttributes::ARCHIVE) {
        windows |= FILE_ATTRIBUTE_ARCHIVE;
    }
    if entry.is_dir() {
        windows |= FILE_ATTRIBUTE_DIRECTORY;
    }
    if windows == 0 {
        // `FILE_ATTRIBUTE_NORMAL` must be used on its own.
        windows = FILE_ATTRIBUTE_NORMAL;
    }
    windows
}

/// Copy the values of a FAT directory entry into an owned snapshot.
fn entry_info(entry: &fatfs::DirEntry<'_, VolumeDevice<Volume>>) -> EntryInfo {
    let is_dir = entry.is_dir();
    EntryInfo {
        attributes: entry_attributes(entry),
        file_size: if is_dir { 0 } else { entry.len() },
        is_dir,
        creation_time: system_time_from_datetime(entry.created()),
        last_access_time: system_time_from_date(entry.accessed()),
        last_write_time: system_time_from_datetime(entry.modified()),
    }
}

/// A synthetic file id: FAT has none, so a hash of the (case insensitive) path is
/// used. Dokany only requires it to be unique per volume.
fn file_index(path: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in path.to_ascii_lowercase().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Truncate a file to zero length (`FILE_SUPERSEDE`/`FILE_OVERWRITE`).
fn truncate_file(filesystem: &FatFs, path: &str) -> OperationResult<()> {
    let mut file = open_file(filesystem, path)?;
    // `File::truncate` truncates at the current position, which is 0 here.
    file.truncate().map_err(fatfs_error)?;
    file.flush().map_err(fatfs_error)
}

/// Create an empty file or directory (`path` must not exist yet).
fn create_entry(filesystem: &FatFs, path: &str, is_dir: bool) -> OperationResult<()> {
    let root = filesystem.root_dir();
    let path = fatfs_path(path);
    if is_dir {
        root.create_dir(&path).map(|_| ()).map_err(fatfs_error)
    } else {
        root.create_file(&path).map(|_| ()).map_err(fatfs_error)
    }
}

/// Delete a file or directory (`fatfs` refuses non-empty directories).
fn delete_entry(filesystem: &FatFs, path: &str) -> OperationResult<()> {
    if path.is_empty() {
        return Err(STATUS_CANNOT_DELETE);
    }
    let root = filesystem.root_dir();
    root.remove(&fatfs_path(path)).map_err(fatfs_error)
}

/// Write `length` zero bytes at the current position.
///
/// FAT has no sparse files, so extending a file by seeking past its end would
/// expose whatever the cluster previously contained; zeroing keeps that
/// deterministic (and is what Windows does when a file is extended).
fn write_zeros<W: Write>(writer: &mut W, mut length: u64) -> OperationResult<()> {
    const CHUNK: usize = 64 * 1024;
    let zeros = vec![0u8; CHUNK.min(length.max(1) as usize)];
    while length > 0 {
        let count = CHUNK.min(length as usize);
        writer.write_all(&zeros[..count]).map_err(fatfs_error)?;
        length -= count as u64;
    }
    Ok(())
}

/// Set the length of an open file, zero filling when growing.
fn set_file_length(file: &mut fatfs::File<'_, VolumeDevice<Volume>>, length: u64) -> OperationResult<()> {
    let size = file.seek(SeekFrom::End(0)).map_err(fatfs_error)?;
    match length.cmp(&size) {
        Ordering::Less => {
            file.seek(SeekFrom::Start(length)).map_err(fatfs_error)?;
            file.truncate().map_err(fatfs_error)?;
        }
        Ordering::Greater => {
            file.seek(SeekFrom::Start(size)).map_err(fatfs_error)?;
            write_zeros(file, length - size)?;
        }
        Ordering::Equal => {}
    }
    file.flush().map_err(fatfs_error)
}

// ---------------------------------------------------------------------------
// FAT timestamps <-> `SystemTime`
//
// FAT stores local time in a format without a timezone; without a timezone
// database in this crate the values are treated as UTC, which is what other
// user-mode FAT drivers do as well.
// ---------------------------------------------------------------------------

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = u32::try_from(year - era * 400).unwrap_or(0);
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = (days - era * 146_097) as u64;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 } as u32;
    ((if month <= 2 { year + 1 } else { year }) as i32, month, day)
}

/// Convert a FAT timestamp to `SystemTime` (invalid FAT dates become the epoch).
fn system_time_from_datetime(date_time: fatfs::DateTime) -> SystemTime {
    let (year, month, day) = (date_time.date.year, date_time.date.month, date_time.date.day);
    if !(1980..=2107).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return UNIX_EPOCH;
    }
    let days = days_from_civil(i32::from(year), u32::from(month), u32::from(day));
    if days < 0 {
        return UNIX_EPOCH;
    }
    let seconds = days as u64 * 86_400
        + u64::from(date_time.time.hour) * 3600
        + u64::from(date_time.time.min) * 60
        + u64::from(date_time.time.sec);
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn system_time_from_date(date: fatfs::Date) -> SystemTime {
    system_time_from_datetime(fatfs::DateTime {
        date,
        time: fatfs::Time { hour: 0, min: 0, sec: 0, millis: 0 },
    })
}

/// Convert a `SystemTime` into the FAT range (1980-01-01 .. 2107-12-31).
fn datetime_from_system_time(time: SystemTime) -> fatfs::DateTime {
    let seconds = time.duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or(0);
    let (mut year, mut month, mut day) = civil_from_days((seconds / 86_400) as i64);
    let time_of_day = seconds % 86_400;
    if year < 1980 {
        (year, month, day) = (1980, 1, 1);
    } else if year > 2107 {
        (year, month, day) = (2107, 12, 31);
    }
    fatfs::DateTime {
        date: fatfs::Date { year: year as u16, month: month as u16, day: day as u16 },
        time: fatfs::Time {
            hour: (time_of_day / 3600) as u16,
            min: ((time_of_day / 60) % 60) as u16,
            sec: (time_of_day % 60) as u16,
            millis: 0,
        },
    }
}

fn date_from_system_time(time: SystemTime) -> fatfs::Date {
    datetime_from_system_time(time).date
}

// ---------------------------------------------------------------------------
// The Dokany handler
// ---------------------------------------------------------------------------

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for VolumeFsHandler {
    type Context = FileContext;

    fn create_file(
        &'h self,
        file_name: &widestring::U16CStr,
        _security_context: &IO_SECURITY_CONTEXT,
        desired_access: ACCESS_MASK,
        file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        _info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        if create_disposition > FILE_MAXIMUM_DISPOSITION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let path = relative_path(&file_name.to_string_lossy());
        let wants_directory = create_options & FILE_DIRECTORY_FILE != 0;
        let wants_file = create_options & FILE_NON_DIRECTORY_FILE != 0;
        if wants_directory && wants_file {
            return Err(STATUS_INVALID_PARAMETER);
        }

        // FAT has no per-file permissions: the only access check we can make is
        // the volume-wide read-only flag.
        let writes = desired_access
            & (FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | GENERIC_WRITE
                | winapi::um::winnt::DELETE)
            != 0;
        if writes {
            reject_if_read_only(self.read_only)?;
        }

        let existing = self.lookup(&path)?;
        let mut new_file_created = false;
        let is_dir = match existing {
            Some(entry) => {
                if wants_directory && !entry.is_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if wants_file && entry.is_dir {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                match create_disposition {
                    FILE_OPEN | FILE_OPEN_IF => {}
                    FILE_CREATE => return Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if entry.is_dir {
                            if create_disposition != FILE_OVERWRITE_IF {
                                return Err(STATUS_FILE_IS_A_DIRECTORY);
                            }
                        } else {
                            reject_if_read_only(self.read_only)?;
                            if entry.attributes & FILE_ATTRIBUTE_READONLY != 0 {
                                return Err(STATUS_ACCESS_DENIED);
                            }
                            truncate_file(&self.lock(), &path)?;
                        }
                    }
                    _ => return Err(STATUS_INVALID_PARAMETER),
                }
                entry.is_dir
            }
            None => {
                if create_disposition == FILE_OPEN || create_disposition == FILE_OVERWRITE {
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                }
                reject_if_read_only(self.read_only)?;
                let as_directory = wants_directory || file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
                create_entry(&self.lock(), &path, as_directory)?;
                new_file_created = true;
                as_directory
            }
        };

        let attributes = existing.map_or_else(
            || if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { file_attributes | FILE_ATTRIBUTE_ARCHIVE },
            |entry| entry.attributes,
        );
        Ok(CreateFileInfo {
            context: FileContext {
                path,
                is_dir,
                attributes,
                delete_on_close: create_options & FILE_DELETE_ON_CLOSE != 0,
            },
            is_dir,
            new_file_created,
        })
    }

    fn cleanup(
        &'h self,
        _file_name: &widestring::U16CStr,
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) {
        // Dokany deletes a file whose handle was opened with delete-on-close by
        // calling `cleanup`, and `delete_file`/`delete_directory` only checked
        // that it may be deleted.
        if !(info.delete_on_close() || context.delete_on_close) || context.path.is_empty() {
            let _ = self.write_back();
            return;
        }
        if self.read_only {
            log::warn!("refusing to delete {}: the volume is mounted read-only", context.path);
            return;
        }
        match delete_entry(&self.lock(), &context.path) {
            Ok(()) => log::debug!("deleted {} on close", context.path),
            Err(status) => log::error!("could not delete {} on close: {status:#010x}", context.path),
        }
        let _ = self.write_back();
    }

    fn close_file(&'h self, _file_name: &widestring::U16CStr, _info: &OperationInfo<'c, 'h, Self>, context: &'c Self::Context) {
        log::trace!("close_file({})", context.path);
        let _ = self.write_back();
    }

    fn read_file(
        &'h self,
        _file_name: &widestring::U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let filesystem = self.lock();
        let mut file = open_file(&filesystem, &context.path)?;
        file.seek(SeekFrom::Start(offset as u64)).map_err(io_error)?;
        let mut read = 0;
        while read < buffer.len() {
            match file.read(&mut buffer[read..]) {
                Ok(0) => break,
                Ok(count) => read += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(io_error(error)),
            }
        }
        log::trace!("read_file({}, {offset}) -> {read} bytes", context.path);
        Ok(read as u32)
    }

    fn write_file(
        &'h self,
        _file_name: &widestring::U16CStr,
        offset: i64,
        buffer: &[u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        reject_if_read_only(self.read_only)?;
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let filesystem = self.lock();
        let mut file = open_file(&filesystem, &context.path)?;
        let size = file.seek(SeekFrom::End(0)).map_err(io_error)?;
        let offset = offset as u64;
        if offset > size {
            file.seek(SeekFrom::Start(size)).map_err(io_error)?;
            write_zeros(&mut file, offset - size)?;
        }
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        file.write_all(buffer).map_err(io_error)?;
        // Writes the directory entry (size, modification time) through the device.
        file.flush().map_err(io_error)?;
        drop(file);
        drop(filesystem);
        log::trace!("write_file({}, {offset}) <- {} bytes", context.path, buffer.len());
        self.write_back()?;
        Ok(buffer.len() as u32)
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &widestring::U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        // `FlushFileBuffers` must reach the disk, so this one does fsync.
        self.device.sync().map_err(|error| {
            log::error!("could not flush the volume: {error}");
            STATUS_UNEXPECTED_IO_ERROR
        })
    }

    fn get_file_information(
        &'h self,
        _file_name: &widestring::U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<FileInfo> {
        let entry = self.lookup(&context.path)?.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(FileInfo {
            attributes: entry.attributes,
            creation_time: entry.creation_time,
            last_access_time: entry.last_access_time,
            last_write_time: entry.last_write_time,
            file_size: entry.file_size,
            number_of_links: 1,
            file_index: file_index(&context.path),
        })
    }

    fn find_files(
        &'h self,
        file_name: &widestring::U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        // The directory handle the query was issued on is authoritative; Dokany
        // filters the results by the search pattern itself (we deliberately do
        // not implement `find_files_with_pattern`, so the library does that).
        let path = if context.is_dir {
            context.path.clone()
        } else {
            split_path(&relative_path(&file_name.to_string_lossy())).0.to_string()
        };
        self.write_back()?;
        let filesystem = self.lock();
        let directory = open_directory(&filesystem, &path)?;
        for entry in directory.iter() {
            let entry = entry.map_err(fatfs_error)?;
            let data = FindData {
                attributes: entry_attributes(&entry),
                creation_time: system_time_from_datetime(entry.created()),
                last_access_time: system_time_from_date(entry.accessed()),
                last_write_time: system_time_from_datetime(entry.modified()),
                file_size: entry_info(&entry).file_size,
                file_name: match U16CString::from_str(entry.file_name()) {
                    Ok(name) => name,
                    Err(_) => {
                        log::warn!("skipping the entry {:?}: it is not a valid UTF-16 name", entry.file_name());
                        continue;
                    }
                },
            };
            match fill_find_data(&data) {
                Ok(()) => {}
                Err(FillDataError::BufferFull) => break,
                Err(FillDataError::NameTooLong) => {
                    log::warn!("skipping an entry with a name longer than the maximum component length");
                }
            }
        }
        Ok(())
    }

    fn set_file_attributes(
        &'h self,
        _file_name: &widestring::U16CStr,
        file_attributes: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        // `fatfs` cannot modify the attributes of an existing entry (the
        // directory entry is only written from the file object's cached copy),
        // so only a no-op request can be honoured.
        let mut requested = file_attributes & TRACKED_ATTRIBUTES;
        if file_attributes & FILE_ATTRIBUTE_NORMAL != 0 {
            // `FILE_ATTRIBUTE_NORMAL` means "no other attributes set".
            requested = 0;
        }
        let current = context.attributes & TRACKED_ATTRIBUTES;
        if requested == current {
            return Ok(());
        }
        log::warn!(
            "cannot set the attributes of {} to {file_attributes:#010x}: fatfs has no API for it (current: {current:#010x})",
            context.path
        );
        Err(STATUS_NOT_SUPPORTED)
    }

    fn set_file_time(
        &'h self,
        _file_name: &widestring::U16CStr,
        creation_time: FileTimeOperation,
        last_access_time: FileTimeOperation,
        last_write_time: FileTimeOperation,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        if context.is_dir {
            // `fatfs` has no API for a directory entry's timestamps (only
            // `fatfs::File` has one) - ignore it rather than failing a copy.
            log::debug!("ignoring a timestamp change for the directory {}", context.path);
            return Ok(());
        }
        let filesystem = self.lock();
        let mut file = open_file(&filesystem, &context.path)?;
        // The setters are deprecated in favour of a custom `TimeProvider`, but
        // they are the only way to set a timestamp for one specific file.
        #[allow(deprecated)]
        {
            if let FileTimeOperation::SetTime(time) = creation_time {
                file.set_created(datetime_from_system_time(time));
            }
            if let FileTimeOperation::SetTime(time) = last_access_time {
                file.set_accessed(date_from_system_time(time));
            }
            if let FileTimeOperation::SetTime(time) = last_write_time {
                file.set_modified(datetime_from_system_time(time));
            }
        }
        file.flush().map_err(io_error)?;
        drop(file);
        drop(filesystem);
        self.write_back()
    }

    fn delete_file(
        &'h self,
        _file_name: &widestring::U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        if context.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        // The actual deletion happens in `cleanup` (delete-on-close).
        Ok(())
    }

    fn delete_directory(
        &'h self,
        _file_name: &widestring::U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        if !context.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if context.path.is_empty() {
            return Err(STATUS_CANNOT_DELETE);
        }
        let filesystem = self.lock();
        if lookup(&filesystem, &context.path)?.is_some() && !directory_is_empty(&filesystem, &context.path)? {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        Ok(())
    }

    fn move_file(
        &'h self,
        _file_name: &widestring::U16CStr,
        new_file_name: &widestring::U16CStr,
        replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        let source = context.path.clone();
        let target = relative_path(&new_file_name.to_string_lossy());
        if source.is_empty() {
            return Err(STATUS_CANNOT_DELETE);
        }
        if target.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if source.eq_ignore_ascii_case(&target) {
            return Ok(());
        }
        let filesystem = self.lock();
        if let Some(entry) = lookup(&filesystem, &target)? {
            if !replace_if_existing {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            if entry.is_dir {
                return Err(STATUS_FILE_IS_A_DIRECTORY);
            }
            if entry.attributes & FILE_ATTRIBUTE_READONLY != 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            delete_entry(&filesystem, &target)?;
        }
        let (target_parent, target_name) = split_path(&target);
        let root = filesystem.root_dir();
        if target_parent.is_empty() {
            root.rename(&fatfs_path(&source), &root, target_name).map_err(fatfs_error)
        } else {
            let destination = open_directory(&filesystem, target_parent)?;
            root.rename(&fatfs_path(&source), &destination, target_name).map_err(fatfs_error)
        }
    }

    fn set_end_of_file(
        &'h self,
        _file_name: &widestring::U16CStr,
        offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        if offset < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let filesystem = self.lock();
        let mut file = open_file(&filesystem, &context.path)?;
        set_file_length(&mut file, offset as u64)?;
        drop(file);
        drop(filesystem);
        self.write_back()
    }

    fn set_allocation_size(
        &'h self,
        _file_name: &widestring::U16CStr,
        alloc_size: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        reject_if_read_only(self.read_only)?;
        if alloc_size < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if context.is_dir {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        // FAT has no separate allocation size: a file always occupies exactly
        // the clusters its size needs. Growing is therefore the same as
        // extending the file; shrinking the allocation without shrinking the
        // file is impossible, so it is ignored (rather than destroying data).
        let filesystem = self.lock();
        let mut file = open_file(&filesystem, &context.path)?;
        let size = file.seek(SeekFrom::End(0)).map_err(io_error)?;
        if (alloc_size as u64) > size {
            set_file_length(&mut file, alloc_size as u64)?;
        } else {
            log::debug!("ignoring a shrinking allocation size for {}", context.path);
        }
        drop(file);
        drop(filesystem);
        self.write_back()
    }

    fn get_disk_free_space(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<DiskSpaceInfo> {
        let filesystem = self.lock();
        let stats = filesystem.stats().map_err(fatfs_error)?;
        let cluster_size = u64::from(stats.cluster_size());
        let byte_count = cluster_size * u64::from(stats.total_clusters());
        let free_byte_count = cluster_size * u64::from(stats.free_clusters());
        Ok(DiskSpaceInfo {
            byte_count,
            free_byte_count,
            // A read-only volume cannot accept any data.
            available_byte_count: if self.read_only { 0 } else { free_byte_count },
        })
    }

    fn get_volume_information(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<VolumeInfo> {
        let mut fs_flags = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
        if self.read_only {
            fs_flags |= FILE_READ_ONLY_VOLUME;
        }
        if self.removable {
            fs_flags |= FILE_REMOVABLE_MEDIA;
        }
        Ok(VolumeInfo {
            name: U16CString::from_str(&self.label).map_err(|_| STATUS_INVALID_PARAMETER)?,
            serial_number: self.volume_id,
            max_component_length: MAX_COMPONENT_LENGTH,
            fs_flags,
            fs_name: U16CString::from_str(self.fat_name).map_err(|_| STATUS_INVALID_PARAMETER)?,
        })
    }

    fn mounted(&'h self, mount_point: &widestring::U16CStr, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        log::info!(
            "{} volume {} mounted at {}",
            self.fat_name,
            self.label,
            mount_point.to_string_lossy()
        );
        Ok(())
    }

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        log::info!("{} volume {} unmounted", self.fat_name, self.label);
        // Last chance to get the data out of the sector cache and onto the disk.
        self.device.sync().map_err(|error| {
            log::error!("could not flush the volume while unmounting: {error}");
            STATUS_UNEXPECTED_IO_ERROR
        })
    }
}

// ---------------------------------------------------------------------------
// Mounting
// ---------------------------------------------------------------------------

/// Convert a mount point into the wide string Dokany expects.
///
/// A single letter is accepted as a drive letter (`"Z"` == `"Z:"`); anything
/// else is passed through and must be a drive letter or an existing, empty
/// directory.
fn mount_point_wide(mount_point: &str) -> Result<U16CString> {
    let trimmed = mount_point.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidParameter("the mount point must not be empty".into()));
    }
    let normalised = if trimmed.len() == 1 && trimmed.chars().all(|character| character.is_ascii_alphabetic()) {
        format!("{trimmed}:")
    } else {
        trimmed.to_string()
    };
    U16CString::from_str(&normalised)
        .map_err(|_| Error::InvalidParameter(format!("{mount_point:?} is not a valid mount point")))
}

/// Describe a Dokany mounting failure.
fn mount_error(error: dokan::FileSystemMountError, mount_point: &str, volume_path: &Path) -> Error {
    use dokan::FileSystemMountError as DokanError;
    let message = format!(
        "could not mount {} at {mount_point}: {error}",
        volume_path.display()
    );
    match error {
        DokanError::DriverInstall | DokanError::Version | DokanError::Start => Error::Unsupported(message),
        _ => Error::InvalidParameter(message),
    }
}

/// Implementation of [`crate::mount`].
pub fn mount(volume_path: &Path, mount_point: &str, open: &OpenOptions, options: &MountOptions) -> Result<()> {
    let volume = Volume::open(volume_path, open)?;
    let device = VolumeDevice::new(volume);
    let filesystem = FileSystem::new(device.clone(), FsOptions::new()).map_err(|error| {
        Error::InvalidParameter(format!(
            "{} does not contain a usable FAT filesystem: {error}",
            volume_path.display()
        ))
    })?;
    let handler = VolumeFsHandler::new(filesystem, device.clone(), options);
    let mount_point_wide = mount_point_wide(mount_point)?;

    let mut flags = MountFlags::empty();
    if options.read_only {
        flags |= MountFlags::WRITE_PROTECT;
    }
    if options.removable {
        flags |= MountFlags::REMOVABLE;
    }
    let mut dokan_options = dokan::MountOptions::default();
    dokan_options.flags = flags;
    dokan_options.sector_size = SECTOR_SIZE as u32;
    dokan_options.allocation_unit_size = handler.cluster_size();
    // `timeout` is left at its default (Dokan's own 15 seconds).

    log::info!(
        "mounting {} ({} volume {}) at {}",
        volume_path.display(),
        handler.fat_name(),
        handler.label(),
        mount_point
    );
    dokan::init();
    let mut mounter = FileSystemMounter::new(&handler, &mount_point_wide, &dokan_options);
    let mounted = match mounter.mount() {
        Ok(mounted) => mounted,
        Err(error) => {
            dokan::shutdown();
            return Err(mount_error(error, mount_point, volume_path));
        }
    };
    log::info!("mounted at {mount_point}; waiting for an unmount request");

    // `FileSystem`'s `Drop` waits until the filesystem is unmounted, which is
    // what makes this function block.
    drop(mounted);
    dokan::shutdown();
    log::info!("{mount_point} was unmounted");
    Ok(())
}

/// Implementation of [`crate::unmount`].
pub fn unmount(mount_point: &str) -> Result<()> {
    let mount_point_wide = mount_point_wide(mount_point)?;
    if dokan::unmount(&mount_point_wide) {
        log::info!("unmounting {mount_point}");
        Ok(())
    } else {
        Err(Error::InvalidParameter(format!(
            "{mount_point} is not mounted (or this process may not unmount it)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_normalised_for_dokan_and_fatfs() {
        assert_eq!(relative_path("\\"), "");
        assert_eq!(relative_path("\\dir\\file.txt"), "dir\\file.txt");
        assert_eq!(relative_path("dir/file.txt"), "dir\\file.txt");
        assert_eq!(relative_path("\\\\dir\\\\file.txt"), "dir\\file.txt");
        assert_eq!(relative_path("\\dir\\"), "dir");
        assert_eq!(fatfs_path("dir\\file.txt"), "dir/file.txt");
        assert_eq!(fatfs_path(""), "/");
        assert_eq!(split_path("dir\\file.txt"), ("dir", "file.txt"));
        assert_eq!(split_path("file.txt"), ("", "file.txt"));
    }

    #[test]
    fn fat_timestamps_round_trip() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let converted = datetime_from_system_time(now);
        assert_eq!(system_time_from_datetime(converted), now);
        // FAT cannot represent dates before 1980 or after 2107.
        assert_eq!(datetime_from_system_time(UNIX_EPOCH).date.year, 1980);
        assert_eq!(system_time_from_datetime(fatfs::DateTime {
            date: fatfs::Date { year: 0, month: 0, day: 0 },
            time: fatfs::Time { hour: 0, min: 0, sec: 0, millis: 0 },
        }), UNIX_EPOCH);
    }

    #[test]
    fn mount_points_are_normalised() {
        assert_eq!(mount_point_wide("z").unwrap().to_string_lossy(), "z:");
        assert_eq!(mount_point_wide("Z:").unwrap().to_string_lossy(), "Z:");
        assert_eq!(mount_point_wide("C:\\mnt\\vault").unwrap().to_string_lossy(), "C:\\mnt\\vault");
        assert!(mount_point_wide("  ").is_err());
    }
}
