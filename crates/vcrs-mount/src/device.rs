//! The glue between `fatfs` and the encrypted volume.
//!
//! `fatfs` talks to a `Read + Write + Seek` block device with arbitrary byte
//! granularity, while the volume layer reads and writes the *decrypted* data
//! area in whole 512-byte sectors. [`VolumeDevice`] bridges the two and adds a
//! small write-back sector cache, so that repeated accesses to the same FAT or
//! directory sector do not cost a full XTS pass every time.
//!
//! ```text
//!   fatfs::FileSystem /\ read / write / seek (byte granular)
//!        v
//!   VolumeDevice        sector cache + sector <-> byte translation
//!        v
//!   Volume::read_data / write_data (512-byte sectors of the data area)
//! ```

use std::{
    fmt,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex, MutexGuard},
};

use vcrs_core::volume::Volume;

/// Size of one volume sector.
///
/// `vcrs-core` file-hosted volumes always use 512-byte sectors (the same value
/// as [`vcrs_core::xts::DATA_UNIT_SIZE`]), and this is what
/// [`crate::format_volume`] formats the FAT filesystem with.
pub const SECTOR_SIZE: usize = 512;

/// Number of sectors kept in the write-back cache (direct mapped).
const CACHE_ENTRIES: usize = 16;

/// Converts a `vcrs-core` error into an `io::Error` for the `fatfs` layer.
fn to_io(err: vcrs_core::error::Error) -> io::Error {
    io::Error::other(format!("volume: {err}"))
}

/// Byte-granular access to the decrypted volume data area.
///
/// Offsets are relative to the **start of the data area**, i.e. offset `0` is
/// the first sector that VeraCrypt encrypts, not the first byte of the
/// container file. This is the same origin `fatfs` uses, so no translation is
/// needed anywhere in the mount layer.
pub trait DataArea {
    /// Length of the accessible data area in bytes.
    fn len(&self) -> u64;

    /// `true` if the data area is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read decrypted bytes at `offset` (relative to the data area).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Write bytes at `offset` (relative to the data area), encrypting them.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;

    /// Flush everything written so far to the host file.
    fn sync(&self) -> io::Result<()>;

    /// Logical sector size of the data area.
    ///
    /// File-hosted VeraCrypt volumes always use 512-byte sectors, which is what
    /// both the FAT filesystem and the iSCSI device expect; the header carries
    /// the value so that a partition-hosted volume (which would declare 4096)
    /// is still translated correctly if we ever host one.
    fn sector_size(&self) -> u32 {
        SECTOR_SIZE as u32
    }
}

impl DataArea for Volume {
    fn len(&self) -> u64 {
        self.data_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        Volume::read_data(self, offset, buf).map_err(to_io)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        Volume::write_data(self, offset, buf).map_err(to_io)
    }

    fn sync(&self) -> io::Result<()> {
        Volume::flush(self).map_err(to_io)
    }

    fn sector_size(&self) -> u32 {
        self.header.sector_size
    }
}

/// Lets [`crate::format_volume`] format a volume it only borrows.
impl DataArea for &mut Volume {
    fn len(&self) -> u64 {
        self.data_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        Volume::read_data(self, offset, buf).map_err(to_io)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        Volume::write_data(self, offset, buf).map_err(to_io)
    }

    fn sync(&self) -> io::Result<()> {
        Volume::flush(self).map_err(to_io)
    }
}

/// The mutable device state: the data area, the sector cache and the current
/// byte position of the `fatfs` I/O stream.
struct DeviceState<A: DataArea> {
    area: A,
    /// `CACHE_ENTRIES` sectors of cached data, indexed by `sector % CACHE_ENTRIES`.
    cache: Vec<u8>,
    /// Which sector each cache slot currently holds.
    cached: [Option<u64>; CACHE_ENTRIES],
    /// Whether a cache slot holds data that is not yet in the volume.
    dirty: [bool; CACHE_ENTRIES],
    position: u64,
}

impl<A: DataArea> DeviceState<A> {
    fn new(area: A) -> Self {
        DeviceState {
            area,
            cache: vec![0u8; CACHE_ENTRIES * SECTOR_SIZE],
            cached: [None; CACHE_ENTRIES],
            dirty: [false; CACHE_ENTRIES],
            position: 0,
        }
    }

    fn slot_of(sector: u64) -> usize {
        (sector % CACHE_ENTRIES as u64) as usize
    }

    /// Write a dirty cache slot back into the volume.
    fn write_back(&mut self, slot: usize) -> io::Result<()> {
        if !self.dirty[slot] {
            return Ok(());
        }
        let sector = match self.cached[slot] {
            Some(sector) => sector,
            None => return Ok(()),
        };
        let begin = slot * SECTOR_SIZE;
        let end = begin + SECTOR_SIZE;
        self.area
            .write_at(sector * SECTOR_SIZE as u64, &self.cache[begin..end])?;
        self.dirty[slot] = false;
        Ok(())
    }

    /// Make `sector` available in the cache and return its slot.
    fn load(&mut self, sector: u64) -> io::Result<usize> {
        let slot = Self::slot_of(sector);
        if self.cached[slot] == Some(sector) {
            return Ok(slot);
        }
        self.write_back(slot)?;
        let begin = slot * SECTOR_SIZE;
        let end = begin + SECTOR_SIZE;
        self.area
            .read_at(sector * SECTOR_SIZE as u64, &mut self.cache[begin..end])?;
        self.cached[slot] = Some(sector);
        self.dirty[slot] = false;
        Ok(slot)
    }

    /// Write back every dirty sector (no host `fsync`, see [`Self::sync_all`]).
    fn write_back_all(&mut self) -> io::Result<()> {
        for slot in 0..CACHE_ENTRIES {
            self.write_back(slot)?;
        }
        Ok(())
    }

    /// Write back every dirty sector and flush the container file.
    fn sync_all(&mut self) -> io::Result<()> {
        self.write_back_all()?;
        self.area.sync()
    }

    /// Number of bytes readable/writable from the current position.
    fn remaining(&self, wanted: usize) -> usize {
        let left = self.area.len().saturating_sub(self.position);
        std::cmp::min(wanted, left as usize)
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.remaining(buf.len());
        let mut done = 0;
        while done < len {
            let sector = self.position / SECTOR_SIZE as u64;
            let offset_in_sector = (self.position % SECTOR_SIZE as u64) as usize;
            let count = std::cmp::min(SECTOR_SIZE - offset_in_sector, len - done);
            let slot = self.load(sector)?;
            let begin = slot * SECTOR_SIZE + offset_in_sector;
            buf[done..done + count].copy_from_slice(&self.cache[begin..begin + count]);
            self.position += count as u64;
            done += count;
        }
        Ok(done)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.remaining(buf.len());
        let mut done = 0;
        while done < len {
            let sector = self.position / SECTOR_SIZE as u64;
            let offset_in_sector = (self.position % SECTOR_SIZE as u64) as usize;
            let count = std::cmp::min(SECTOR_SIZE - offset_in_sector, len - done);
            let slot = self.load(sector)?;
            let begin = slot * SECTOR_SIZE + offset_in_sector;
            self.cache[begin..begin + count].copy_from_slice(&buf[done..done + count]);
            self.dirty[slot] = true;
            self.position += count as u64;
            done += count;
        }
        Ok(done)
    }

    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.area.len();
        let new = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::Current(delta) => self.position as i128 + delta as i128,
            SeekFrom::End(delta) => len as i128 + delta as i128,
        };
        if new < 0 || new > len as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside of the volume data area",
            ));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

impl<A: DataArea> Drop for DeviceState<A> {
    fn drop(&mut self) {
        if let Err(err) = self.sync_all() {
            log::error!("could not flush the volume data area: {err}");
        }
    }
}

/// A cached, byte-granular block device over a volume data area.
///
/// Cloning is cheap and shares the underlying volume, the byte position and the
/// sector cache, which is how the mount layer can still flush the volume while
/// `fatfs` owns the device. All access is serialised through a mutex.
pub struct VolumeDevice<A: DataArea = Volume> {
    inner: Arc<Mutex<DeviceState<A>>>,
}

impl<A: DataArea> Clone for VolumeDevice<A> {
    fn clone(&self) -> Self {
        VolumeDevice { inner: Arc::clone(&self.inner) }
    }
}

impl<A: DataArea> VolumeDevice<A> {
    /// Create a device over `area`. The `fatfs` stream starts at offset 0.
    pub fn new(area: A) -> Self {
        VolumeDevice { inner: Arc::new(Mutex::new(DeviceState::new(area))) }
    }

    /// Length of the underlying data area in bytes.
    pub fn len(&self) -> u64 {
        self.lock().area.len()
    }

    /// `true` if the underlying data area is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Push the cached sectors into the volume without an `fsync`.
    ///
    /// This is enough to keep the volume consistent for the current session (the
    /// data has been handed to the operating system); it is what every
    /// file-close uses.
    pub fn write_back(&self) -> io::Result<()> {
        self.lock().write_back_all()
    }

    /// Push the cached sectors into the volume and `fsync` the container file.
    pub fn sync(&self) -> io::Result<()> {
        self.lock().sync_all()
    }

    fn lock(&self) -> MutexGuard<'_, DeviceState<A>> {
        // A panic in an operation must not make the mounted volume unusable.
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

impl<A: DataArea + fmt::Debug> fmt::Debug for VolumeDevice<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VolumeDevice").field("len", &self.len()).finish_non_exhaustive()
    }
}

impl<A: DataArea> Read for VolumeDevice<A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

impl<A: DataArea> Write for VolumeDevice<A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<A: DataArea> Seek for VolumeDevice<A> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.lock().seek(pos)
    }
}
