//! The Windows API calls behind the iSCSI work, with no PowerShell in between.
//!
//! Every `powershell` call costs a process launch (0.3-0.7 s) and, for the storage
//! cmdlets, a module import of one to three seconds — and the CLI makes several of
//! them per mount and per dismount. What they ask for is a handful of Win32 calls, so
//! each one that is replaced here is a second off both commands. This module holds the
//! replacements as they land; the policy (what to do when a call fails, how long to
//! wait) stays with the caller.

use anyhow::Result;

/// How a Windows service is doing, in the words the rest of the CLI prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Paused,
    Unknown(u32),
}

impl ServiceState {
    /// The state as a word, the way `Get-Service` would have said it.
    pub(crate) fn word(self) -> &'static str {
        match self {
            ServiceState::NotInstalled => "not installed",
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "starting",
            ServiceState::StopPending => "stopping",
            ServiceState::Running => "running",
            ServiceState::Paused => "paused",
            // The caller prints whatever comes back, so an unknown code is not fatal.
            ServiceState::Unknown(_) => "in an unknown state",
        }
    }

    /// The state code the service manager uses, turned into something readable.
    #[cfg(windows)]
    fn from_code(code: u32) -> Self {
        // `SERVICE_STOPPED`..`SERVICE_CONTINUE_PENDING` in winapi's winsvc.h order.
        match code {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::Paused,
            6 => ServiceState::Paused,
            7 => ServiceState::StartPending,
            other => ServiceState::Unknown(other),
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::ServiceState;
    use anyhow::{bail, Result};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winsvc::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, StartServiceW,
        SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_START,
        SERVICE_STATUS_PROCESS,
    };

    /// `ERROR_SERVICE_DOES_NOT_EXIST` — the one failure that is an answer, not an error.
    const NO_SUCH_SERVICE: u32 = 1060;
    /// `ERROR_SERVICE_ALREADY_RUNNING` — somebody else started it first.
    const ALREADY_RUNNING: u32 = 1056;

    /// The service manager wants UTF-16 names and knows nothing of Rust strings.
    fn wide(name: &str) -> Vec<u16> {
        OsStr::new(name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub(super) fn service_state(name: &str) -> Result<ServiceState> {
        unsafe {
            let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                bail!(
                    "opening the service control manager: Windows error {}",
                    GetLastError()
                );
            }
            let service = OpenServiceW(manager, wide(name).as_ptr(), SERVICE_QUERY_STATUS);
            if service.is_null() {
                let error = GetLastError();
                CloseServiceHandle(manager);
                if error == NO_SUCH_SERVICE {
                    return Ok(ServiceState::NotInstalled);
                }
                bail!("opening the service `{name}`: Windows error {error}");
            }
            let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut needed: DWORD = 0;
            let asked = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut SERVICE_STATUS_PROCESS as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as DWORD,
                &mut needed,
            );
            let error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            if asked == 0 {
                bail!("asking the service manager about `{name}`: Windows error {error}");
            }
            Ok(ServiceState::from_code(status.dwCurrentState))
        }
    }

    pub(super) fn file_system(letter: char) -> Option<String> {
        use winapi::um::fileapi::GetVolumeInformationW;
        let root = wide(&format!("{letter}:\\"));
        let mut name = [0u16; 64];
        // The volume name and serial number are not wanted, only the file system.
        let asked = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                name.as_mut_ptr(),
                name.len() as DWORD,
            )
        };
        if asked == 0 {
            return None;
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        Some(String::from_utf16_lossy(&name[..len]))
    }

    pub(super) fn start_service(name: &str) -> Result<()> {
        unsafe {
            let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if manager.is_null() {
                bail!(
                    "opening the service control manager: Windows error {}",
                    GetLastError()
                );
            }
            let service = OpenServiceW(
                manager,
                wide(name).as_ptr(),
                SERVICE_START | SERVICE_QUERY_STATUS,
            );
            if service.is_null() {
                let error = GetLastError();
                CloseServiceHandle(manager);
                bail!("opening the service `{name}` to start it: Windows error {error}");
            }
            let started = StartServiceW(service, 0, std::ptr::null_mut());
            let error = GetLastError();
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            if started == 0 && error != ALREADY_RUNNING {
                bail!("starting the service `{name}`: Windows error {error}");
            }
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ServiceState;
    use anyhow::{bail, Result};

    pub(super) fn service_state(_name: &str) -> Result<ServiceState> {
        bail!("services are a Windows notion; there are none here")
    }

    pub(super) fn file_system(_letter: char) -> Option<String> {
        None
    }

    pub(super) fn start_service(_name: &str) -> Result<()> {
        bail!("services are a Windows notion; there are none here")
    }
}

/// The file system on a drive letter (`NTFS`, `FAT32`), or `None` when the volume has
/// none — a disk that has just been attached and has not been formatted yet.
pub(crate) fn file_system(letter: char) -> Option<String> {
    platform::file_system(letter)
}

/// What a service is doing right now (`msiscsi`, for the iSCSI work).
pub(crate) fn service_state(name: &str) -> Result<ServiceState> {
    platform::service_state(name)
}

/// Ask the service manager to start a service. A service that is already running is
/// not an error.
pub(crate) fn start_service(name: &str) -> Result<()> {
    platform::start_service(name)
}

/// A wide string with the terminating NUL Windows wants.
fn nul_terminated(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The text of a wide buffer, up to its terminating NUL.
fn wide_to_string(wide: &[u16]) -> String {
    let end = wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

/// The volume behind a drive letter, and the disk that volume is on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(windows)]
pub(crate) struct VolumeOnDisk {
    /// The volume's own name, `\\?\Volume{…}\` — what the mount-point API takes.
    pub(crate) volume: String,
    /// The physical disk the volume starts on.
    pub(crate) disk: u32,
    /// The partition number Windows gives that volume.
    pub(crate) partition: u32,
}

/// The volume a drive letter is a mount point on, and the disk behind it.
///
/// This is what `Get-Partition -DriveLetter` plus `Get-Disk` answer, in two calls: a
/// drive letter is a mount point, so Windows can name the volume for it, and a volume
/// can be asked which disk extents it covers.  It needs no elevation for a volume the
/// caller can read.
#[cfg(windows)]
pub(crate) fn volume_of_letter(letter: char) -> Result<VolumeOnDisk> {
    let letter = letter.to_ascii_uppercase();
    if !letter.is_ascii_alphabetic() {
        anyhow::bail!("{letter} is not a drive letter");
    }
    let mount_point = nul_terminated(&format!("{letter}:\\"));
    let mut name = [0u16; 512];
    let ok = unsafe {
        winapi::um::fileapi::GetVolumeNameForVolumeMountPointW(
            mount_point.as_ptr(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("{letter}: is not a volume Windows can name ({err})");
    }
    let volume = wide_to_string(&name);

    // Opening the volume is how its disk extents are asked for.  The volume is mounted
    // and in use by everyone else, so the share flags matter, and it is opened through
    // its own name rather than the letter (`\\?\Volume{…}\`).
    // The volume is opened by its DOS name (`X:` with the device prefix CreateFile
    // wants): Windows answers "path not found" for the volume GUID name that was just
    // read back.  No access rights are asked for (the ioctl is FILE_ANY_ACCESS), and
    // both share flags are needed because the volume is mounted and in use.
    const SLASH: char = '\\';
    let path = nul_terminated(&format!("{SLASH}{SLASH}.{SLASH}{letter}:"));
    let handle = unsafe {
        winapi::um::fileapi::CreateFileW(
            path.as_ptr(),
            0,
            winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("opening {volume} to ask which disk it is on: {err}");
    }
    let mut buffer = [0u8; 1024];
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let err = std::io::Error::last_os_error();
    if ok == 0 {
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        anyhow::bail!("asking which disk {volume} is on: {err}");
    }
    // `VOLUME_DISK_EXTENTS` is a count, four bytes of alignment padding, then the
    // extents — a disk number, more padding, and two 64 bit integers each.
    let extents = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if extents == 0 || returned < 32 {
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        anyhow::bail!("{volume} covers no disk extents");
    }
    let disk = u32::from_ne_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);

    // The same handle answers which partition on that disk the volume is.  The drive
    // layout of a disk Windows has just built (the disk an iSCSI login creates) cannot
    // be trusted to name it, this can: `STORAGE_DEVICE_NUMBER` is a device type, a
    // device number and a partition number, three u32s.
    let mut device = [0u8; 32];
    let mut got = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_STORAGE_GET_DEVICE_NUMBER,
            std::ptr::null_mut(),
            0,
            device.as_mut_ptr() as *mut winapi::ctypes::c_void,
            device.len() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    let partition = if ok != 0 && got >= 12 {
        u32::from_ne_bytes([device[8], device[9], device[10], device[11]])
    } else {
        0
    };
    Ok(VolumeOnDisk {
        volume,
        disk,
        partition,
    })
}

/// Windows' flags for `DefineDosDeviceW` (winbase.h).
#[cfg(windows)]
const DDD_RAW_TARGET_PATH: u32 = 0x0000_0001;
#[cfg(windows)]
const DDD_REMOVE_DEFINITION: u32 = 0x0000_0002;
#[cfg(windows)]
const DDD_EXACT_MATCH_ON_REMOVE: u32 = 0x0000_0004;

/// Take a drive letter off whatever volume has it.
///
/// The letter is a mount point on the volume *and* a DOS device in the session, and a
/// letter Windows kept after the volume went away only needs the second one gone.  So
/// this removes the mount point first — the supported way, which keeps the mount
/// manager's own records straight — and falls back to the DOS device for a letter that
/// has no volume under it any more.  A letter that is already gone is a success: that
/// is the state the caller wanted.
#[cfg(windows)]
/// Take the filesystem off a volume, so that the session behind it can be logged out.
///
/// Windows refuses to log an iSCSI session out while a device on it is in use — "The
/// session cannot be logged out since a device on that session is currently being
/// used." — and a mounted filesystem is exactly that. Taking the drive letter away and
/// offlining the disk are not enough on their own: the filesystem itself has to be told
/// to let go, which is what `FSCTL_LOCK_VOLUME` (it only succeeds once everything that
/// has the volume open has closed it) and `FSCTL_DISMOUNT_VOLUME` do. This is the
/// sequence VeraCrypt's own unmount runs; without it a dismount leaves the session
/// logged in, and the next attach has to clear the leftover before it can log in.
pub(crate) fn dismount_volume(letter: char, wait: std::time::Duration) -> Result<()> {
    const SLASH: char = '\\';
    let letter = letter.to_ascii_uppercase();
    let path = nul_terminated(&format!("{SLASH}{SLASH}.{SLASH}{letter}:"));
    let handle = unsafe {
        winapi::um::fileapi::CreateFileW(
            path.as_ptr(),
            winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE,
            winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        // A volume that is already gone needs nothing done to it.
        if err.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        anyhow::bail!("opening {letter}: to take the filesystem off it: {err}");
    }

    // The lock only succeeds once every handle on the volume has closed — Explorer, an
    // indexer, a shell sitting in the directory — so it is given a few goes: the volume
    // is in use until it is not, and waiting is what VeraCrypt does here too.
    let deadline = std::time::Instant::now() + wait;
    let locked = loop {
        match control(handle, winapi::um::winioctl::FSCTL_LOCK_VOLUME) {
            Ok(()) => break Ok(()),
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    break Err(err);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    };
    // Dismounting is what actually releases the device the session is holding. The lock
    // is deliberately kept until the handle closes: nothing may open the volume again
    // between here and the logout.
    let result = locked.and_then(|()| {
        control(handle, winapi::um::winioctl::FSCTL_DISMOUNT_VOLUME)
            .map_err(|err| err.context(format!("taking the filesystem off {letter}:")))
            // VeraCrypt's unmount refreshes the volume's properties immediately after the
            // dismount, and the mount manager needs that to see the volume as gone: without
            // it the session still counts as "currently being used" when the logout comes,
            // and the logout is refused.
            .and_then(|()| control(handle, winapi::um::winioctl::IOCTL_DISK_UPDATE_PROPERTIES))
    });
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    result
}

/// One `DeviceIoControl` that takes no input and returns nothing.
fn control(handle: winapi::um::winnt::HANDLE, code: u32) -> Result<()> {
    let mut returned: u32 = 0;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            code,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("the volume control 0x{code:08x}: {err}");
    }
    Ok(())
}

pub(crate) fn release_letter(letter: char) -> Result<()> {
    let letter = letter.to_ascii_uppercase();
    if !letter.is_ascii_alphabetic() {
        anyhow::bail!("{letter} is not a drive letter");
    }
    let mount_point = nul_terminated(&format!("{letter}:\\"));
    let ok = unsafe { winapi::um::fileapi::DeleteVolumeMountPointW(mount_point.as_ptr()) };
    if ok != 0 {
        return Ok(());
    }
    let first = std::io::Error::last_os_error();

    let name = nul_terminated(&format!("{letter}:"));
    let ok = unsafe {
        winapi::um::fileapi::DefineDosDeviceW(
            DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            name.as_ptr(),
            std::ptr::null(),
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let second = std::io::Error::last_os_error();
    if second.kind() == std::io::ErrorKind::NotFound {
        return Ok(());
    }
    anyhow::bail!("taking {letter}: away: as a mount point {first}, as a DOS device {second}");
}

// ---------------------------------------------------------------- the disks

/// `SET_DISK_ATTRIBUTES`, as winioctl.h declares it.  winapi has the ioctl codes but
/// not the structures.
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SetDiskAttributes {
    version: u32,
    persist: u8,
    _reserved1: [u8; 3],
    attributes: u64,
    attributes_mask: u64,
    _reserved2: [u32; 4],
}

/// `GET_DISK_ATTRIBUTES`: a version, a reserved word, then the attribute pair.
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetDiskAttributes {
    version: u32,
    reserved: u32,
    _reserved_attributes: u64,
    attributes: u64,
}

/// `DISK_ATTRIBUTE_OFFLINE` (winioctl.h).
#[cfg(windows)]
const DISK_ATTRIBUTE_OFFLINE: u64 = 0x0000_0000_0000_0001;

/// Open a physical disk.  `write` asks for the access the attribute ioctl needs.
#[cfg(windows)]
fn open_disk(number: u32, write: bool) -> Result<winapi::um::winnt::HANDLE> {
    const SLASH: char = '\\';
    let path = nul_terminated(&format!("{SLASH}{SLASH}.{SLASH}PhysicalDrive{number}"));
    let access = if write {
        winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE
    } else {
        winapi::um::winnt::GENERIC_READ
    };
    let handle = unsafe {
        winapi::um::fileapi::CreateFileW(
            path.as_ptr(),
            access,
            winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("opening disk {number}: {err}");
    }
    Ok(handle)
}

/// Whether Windows has this disk offline.
#[cfg(windows)]
/// Tell Windows the medium is gone, the way VeraCrypt's unmount does for a device-hosted
/// volume: our disk is presented as removable, so ejecting it makes the storage stack drop
/// the disk and its volumes at once. That is what the iSCSI session needs before it can be
/// logged out — Windows otherwise answers "a device on that session is currently being used"
/// even after the disk device has been removed from the device tree.
pub(crate) fn eject_media(number: u32) -> Result<()> {
    let handle = open_disk(number, true)?;
    let result = control(handle, winapi::um::winioctl::IOCTL_STORAGE_EJECT_MEDIA);
    unsafe {
        winapi::um::handleapi::CloseHandle(handle);
    }
    result.map_err(|err| err.context(format!("ejecting the medium of disk {number}")))
}

pub(crate) fn disk_is_offline(number: u32) -> Result<bool> {
    let handle = open_disk(number, false)?;
    let mut attributes = GetDiskAttributes {
        version: std::mem::size_of::<GetDiskAttributes>() as u32,
        ..Default::default()
    };
    let mut returned = 0u32;
    let mut ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_DISK_GET_DISK_ATTRIBUTES,
            &mut attributes as *mut _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<GetDiskAttributes>() as u32,
            &mut attributes as *mut _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<GetDiskAttributes>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    // The version field is the structure's size in the newer headers and 1 in the
    // older ones; both are cheap to try, so both are.
    if ok == 0 {
        attributes.version = 1;
        ok = unsafe {
            winapi::um::ioapiset::DeviceIoControl(
                handle,
                winapi::um::winioctl::IOCTL_DISK_GET_DISK_ATTRIBUTES,
                &mut attributes as *mut _ as *mut winapi::ctypes::c_void,
                std::mem::size_of::<GetDiskAttributes>() as u32,
                &mut attributes as *mut _ as *mut winapi::ctypes::c_void,
                std::mem::size_of::<GetDiskAttributes>() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
    }
    let err = std::io::Error::last_os_error();
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    if ok == 0 {
        anyhow::bail!("asking whether disk {number} is offline: {err}");
    }
    Ok(attributes.attributes & DISK_ATTRIBUTE_OFFLINE != 0)
}

/// Take a disk offline, or bring it back, the way `Set-Disk -IsOffline` does.
///
/// A disk has to be offline before the initiator will let its session go: it refuses to
/// log a session out while a device on that session is still in use, and an offline
/// disk is not in use.  Nothing is done when the disk already has the wanted state, so
/// this is safe to call on a disk Windows has handled already.
#[cfg(windows)]
pub(crate) fn set_disk_offline(number: u32, offline: bool) -> Result<()> {
    if disk_is_offline(number)? == offline {
        return Ok(());
    }
    let handle = open_disk(number, true)?;
    let wanted = if offline { DISK_ATTRIBUTE_OFFLINE } else { 0 };
    let mut last = None;
    for version in [std::mem::size_of::<SetDiskAttributes>() as u32, 1] {
        let mut attributes = SetDiskAttributes {
            version,
            persist: 1,
            attributes: wanted,
            attributes_mask: DISK_ATTRIBUTE_OFFLINE,
            ..Default::default()
        };
        let mut returned = 0u32;
        let ok = unsafe {
            winapi::um::ioapiset::DeviceIoControl(
                handle,
                winapi::um::winioctl::IOCTL_DISK_SET_DISK_ATTRIBUTES,
                &mut attributes as *mut _ as *mut winapi::ctypes::c_void,
                std::mem::size_of::<SetDiskAttributes>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            unsafe { winapi::um::handleapi::CloseHandle(handle) };
            return Ok(());
        }
        last = Some(std::io::Error::last_os_error());
    }
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    let err = last.expect("one of the two versions ran");
    anyhow::bail!(
        "taking disk {number} {offline_failed}: {err}",
        offline_failed = if offline { "offline" } else { "online again" }
    );
}

// ------------------------------------------------------------- disk devices

/// A device Windows has, with the id `pnputil` and the Config Manager take.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiskDevice {
    /// The instance id, such as `SCSI\DISK&VEN_VC-RS&PROD_VERACRYPT_VOLUME\1&…`.
    pub(crate) instance_id: String,
    /// The name Windows shows for it, which is what the caller filters on.
    pub(crate) name: String,
}

// winapi has `SP_DEVINFO_DATA` itself, so there is no structure to write here; only the
// interface class GUID is left to name.

/// `GUID_DEVINTERFACE_DISK`: the interface class every disk device answers to.
#[cfg(windows)]
const GUID_DEVINTERFACE_DISK: winapi::shared::guiddef::GUID = winapi::shared::guiddef::GUID {
    Data1: 0x53F5_6307,
    Data2: 0xB6BF,
    Data3: 0x11D0,
    Data4: [0x94, 0xF2, 0x00, 0xA0, 0xC9, 0x1E, 0xFB, 0x8B],
};

/// The disk devices Windows currently has whose name contains `matching`.
///
/// This is what `Get-PnpDevice -Class DiskDrive` answers, without a cmdlet import: the
/// device interfaces are enumerated and each one's friendly name is read, which is the
/// name the caller knows the volume by.
#[cfg(windows)]
pub(crate) fn disk_devices(matching: &str) -> Result<Vec<DiskDevice>> {
    const DIGCF_PRESENT: u32 = 0x0000_0002;
    const DIGCF_DEVICEINTERFACE: u32 = 0x0000_0010;
    const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;
    use winapi::um::setupapi::{
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
        SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
    };

    let set = unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_DISK,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("listing the disk devices: {err}");
    }

    let mut found = Vec::new();
    for index in 0u32.. {
        let mut info: winapi::um::setupapi::SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<winapi::um::setupapi::SP_DEVINFO_DATA>() as u32;
        let ok = unsafe { SetupDiEnumDeviceInfo(set, index, &mut info) };
        if ok == 0 {
            break;
        }
        let mut name = [0u16; 256];
        let mut kind = 0u32;
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set,
                &mut info,
                SPDRP_FRIENDLYNAME,
                &mut kind,
                name.as_mut_ptr() as *mut u8,
                (name.len() * std::mem::size_of::<u16>()) as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            continue;
        }
        let name = wide_to_string(&name);
        if !name.contains(matching) {
            continue;
        }
        let mut instance = [0u16; 512];
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(
                set,
                &mut info,
                instance.as_mut_ptr(),
                instance.len() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            continue;
        }
        found.push(DiskDevice {
            instance_id: wide_to_string(&instance),
            name,
        });
    }
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    Ok(found)
}

// ------------------------------------------------------------- the disk list

/// The widest physical-drive number that is looked at.  A machine with more drives
/// than this is not the one this is for, and a drive that is not there costs one
/// failed `CreateFileW`.
#[cfg(windows)]
const MAX_DISKS: u32 = 64;

/// `STORAGE_PROPERTY_QUERY`, as winioctl.h declares it: two words and a byte of
/// additional parameters (which nothing uses).
#[cfg(windows)]
#[repr(C)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional: [u8; 1],
}

/// Every drive letter Windows has, straight from the kernel.
#[cfg(windows)]
pub(crate) fn drive_letters() -> Vec<char> {
    let mask = unsafe { winapi::um::fileapi::GetLogicalDrives() };
    (0..26u32)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| (b'A' + bit as u8) as char)
        .collect()
}

/// Ask a disk what it is (`IOCTL_STORAGE_QUERY_PROPERTY`), which is the INQUIRY
/// product string the SCSI target answers with.
#[cfg(windows)]
fn disk_product(handle: winapi::um::winnt::HANDLE) -> Result<String> {
    const PROPERTY_STANDARD_QUERY: u32 = 0;
    const STORAGE_DEVICE_PROPERTY: u32 = 0;
    /// In `STORAGE_DEVICE_DESCRIPTOR`, `ProductIdOffset` is the u32 at byte 16: the
    /// vendor id is at 12, the revision at 20 and the serial at 24.
    const PRODUCT_OFFSET_AT: usize = 16;
    let mut query = StoragePropertyQuery {
        property_id: STORAGE_DEVICE_PROPERTY,
        query_type: PROPERTY_STANDARD_QUERY,
        additional: [0],
    };
    let mut buffer = [0u8; 1024];
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_STORAGE_QUERY_PROPERTY,
            &mut query as *mut _ as *mut winapi::ctypes::c_void,
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("asking a disk what it is: {err}");
    }
    let returned = (returned as usize).min(buffer.len());
    if returned < PRODUCT_OFFSET_AT + 4 {
        return Ok(String::new());
    }
    let offset =
        u32::from_le_bytes(buffer[PRODUCT_OFFSET_AT..PRODUCT_OFFSET_AT + 4].try_into()?) as usize;
    if offset == 0 || offset >= returned {
        return Ok(String::new());
    }
    let end = buffer[offset..returned]
        .iter()
        .position(|byte| *byte == 0)
        .map(|at| offset + at)
        .unwrap_or(returned);
    Ok(String::from_utf8_lossy(&buffer[offset..end])
        .trim()
        .to_string())
}

/// How big a disk is (`IOCTL_DISK_GET_LENGTH_INFO` answers with one `LARGE_INTEGER`).
#[cfg(windows)]
fn disk_length(handle: winapi::um::winnt::HANDLE) -> Result<u64> {
    let mut length = [0u8; 8];
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null_mut(),
            0,
            length.as_mut_ptr() as *mut winapi::ctypes::c_void,
            length.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("asking a disk how big it is: {err}");
    }
    Ok(u64::from_le_bytes(length))
}

/// The partition numbers of a disk (`IOCTL_DISK_GET_DRIVE_LAYOUT_EX`).
///
/// The layout is a header with a flexible array of entries after it, so it is read as
/// bytes rather than as a structure: `PartitionCount` is the u32 at 4, the entries
/// start at 24, and each is 72 bytes with its `PartitionNumber` at 24 and its
/// `PartitionLength` at 16.  A disk with no partition table (a raw volume) answers
/// with a count of zero, which is the answer wanted as well.
#[cfg(windows)]
fn disk_partitions(handle: winapi::um::winnt::HANDLE) -> Result<Vec<u32>> {
    // `DRIVE_LAYOUT_INFORMATION_EX` is a partition style, a partition count, a 32 byte
    // union of the MBR and GPT style information, and then one 144 byte
    // `PARTITION_INFORMATION_EX` per partition — inside which the length sits at offset
    // 16 and the partition number at 24.
    const HEADER: usize = 40;
    const ENTRY: usize = 144;
    let mut buffer = vec![0u8; 4096];
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("asking a disk for its partitions: {err}");
    }
    let count = u32::from_le_bytes(buffer[4..8].try_into()?) as usize;
    let mut numbers = Vec::new();
    for index in 0..count {
        let base = HEADER + index * ENTRY;
        if base + 28 > buffer.len() {
            break;
        }
        let length = i64::from_le_bytes(buffer[base + 16..base + 24].try_into()?);
        let number = u32::from_le_bytes(buffer[base + 24..base + 28].try_into()?);
        if length > 0 {
            numbers.push(number);
        }
    }
    Ok(numbers)
}

/// Every disk whose INQUIRY product string contains `product`, with the partition
/// Windows sees on it, its drive letter and its file system.
///
/// This is what a `Get-Disk` + `Get-Partition` pass used to answer, from the same
/// places: the product string says which disks are ours, the drive layout gives the
/// partitions, the mount points give the letter, and the volume gives the file
/// system.  Every call is an ioctl, so the whole listing costs milliseconds where the
/// cmdlet import alone used to cost seconds — and a caller that polls can poll.
#[cfg(windows)]
pub(crate) fn vcrs_disks(product: &str) -> Result<Vec<crate::attach::DiskInfo>> {
    // The letters Windows has, with the disk each one sits on.  A letter is the only
    // thing that names a volume, and a volume is the only thing that names a file
    // system, so a disk listing starts here.
    let mut letters: Vec<(char, u32, u32)> = Vec::new();
    for letter in drive_letters() {
        if let Ok(on) = volume_of_letter(letter) {
            letters.push((letter, on.disk, on.partition));
        }
    }

    let wanted = product.to_ascii_uppercase();
    let mut found = Vec::new();
    for number in 0..MAX_DISKS {
        let Ok(handle) = open_disk(number, false) else {
            continue;
        };
        let listing = (|| -> Result<(String, u64, Vec<u32>)> {
            Ok((
                disk_product(handle)?,
                disk_length(handle)?,
                disk_partitions(handle)?,
            ))
        })();
        unsafe { winapi::um::handleapi::CloseHandle(handle) };
        let Ok((product_id, size, partitions)) = listing else {
            continue;
        };
        if !product_id.to_ascii_uppercase().contains(&wanted) {
            continue;
        }
        let on_letter = letters.iter().find(|(_, disk, _)| *disk == number);
        let letter = on_letter.map(|(letter, _, _)| *letter);
        // The partition number comes from the volume Windows mounted, and only falls
        // back to the drive layout — which misreads a disk whose layout Windows has just
        // built (an iSCSI disk) — when no letter names the volume yet.
        let part_number = on_letter
            .map(|(_, _, partition)| *partition)
            .filter(|partition| *partition > 0)
            .or_else(|| partitions.first().copied());
        let partition = part_number.map(|number| crate::attach::PartitionInfo {
            number,
            letter,
            file_system: letter.and_then(file_system),
        });
        found.push(crate::attach::DiskInfo {
            number,
            size,
            partition,
            letter,
        });
    }
    Ok(found)
}

/// The volume on a disk (a `\?\Volume{…}\` name), which is what a mount point is
/// made of when a volume has no letter yet.
#[cfg(windows)]
/// Ask Windows to read a disk again (`IOCTL_DISK_UPDATE_PROPERTIES`).
///
/// A disk that has just appeared can have its partition table read before the volume
/// underneath the partition exists — the Storage cmdlets refresh the disk for
/// themselves, and this is the ioctl that does it at the Win32 level.
#[cfg(windows)]
pub(crate) fn refresh_disk(number: u32) -> Result<()> {
    let handle = open_disk(number, true)?;
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_DISK_UPDATE_PROPERTIES,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let err = std::io::Error::last_os_error();
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    if ok == 0 {
        anyhow::bail!("asking Windows to look at disk {number} again: {err}");
    }
    Ok(())
}

/// The drive letters the volumes of a disk carry.
///
/// Windows puts a letter of its own on a volume the moment its disk arrives, so a
/// freshly attached container often already wears one (`D:`, the next free letter)
/// before the requested letter is set — this is how that letter is found again, so
/// that it can be taken off before the asked-for one goes on.
pub(crate) fn letters_on_disk(number: u32) -> Vec<char> {
    drive_letters()
        .into_iter()
        .filter(|letter| {
            volume_of_letter(*letter)
                .map(|volume| volume.disk == number)
                .unwrap_or(false)
        })
        .collect()
}

pub(crate) fn volume_on_disk(number: u32) -> Result<String> {
    let mut buffer = [0u16; 1024];
    let find =
        unsafe { winapi::um::fileapi::FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if find == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("listing the volumes: {err}");
    }
    let mut found = None;
    loop {
        // The name Windows returns already ends in a backslash and is used as it is.
        let candidate = wide_to_string(&buffer);
        if let Ok(on) = volume_disk(&candidate) {
            if on == number {
                found = Some(candidate);
                break;
            }
        }
        let next = unsafe {
            winapi::um::fileapi::FindNextVolumeW(find, buffer.as_mut_ptr(), buffer.len() as u32)
        };
        if next == 0 {
            break;
        }
    }
    unsafe { winapi::um::fileapi::FindVolumeClose(find) };
    found.ok_or_else(|| anyhow::anyhow!("no volume is on disk {number}"))
}

/// The disk a volume handle starts on (`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`).
#[cfg(windows)]
fn disk_extents(handle: winapi::um::winnt::HANDLE) -> Result<u32> {
    let mut buffer = [0u8; 1024];
    let mut returned = 0u32;
    let ok = unsafe {
        winapi::um::ioapiset::DeviceIoControl(
            handle,
            winapi::um::winioctl::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr() as *mut winapi::ctypes::c_void,
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("asking which disk a volume is on: {err}");
    }
    // `VOLUME_DISK_EXTENTS` is a count, four bytes of alignment padding, then the
    // extents — a disk number, more padding, and two 64 bit integers each.
    if (returned as usize) < 12 {
        anyhow::bail!("a volume answered without a disk extent");
    }
    Ok(u32::from_le_bytes(buffer[8..12].try_into()?))
}

/// The disk a volume sits on, from the volume's own path.
#[cfg(windows)]
fn volume_disk(volume: &str) -> Result<u32> {
    // A volume name ends in a backslash as Windows lists it (`\\?\Volume{…}\`), and
    // opening it *with* that backslash fails with ERROR_PATH_NOT_FOUND: the handle
    // wants the name without it.
    let path = nul_terminated(volume.trim_end_matches(char::from(92u8)));
    let handle = unsafe {
        winapi::um::fileapi::CreateFileW(
            path.as_ptr(),
            0,
            winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            winapi::um::fileapi::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("opening the volume {volume}: {err}");
    }
    let result = disk_extents(handle);
    unsafe { winapi::um::handleapi::CloseHandle(handle) };
    result
}

/// Put a volume on a drive letter, which is what `Set-Partition -NewDriveLetter`
/// does underneath.
#[cfg(windows)]
pub(crate) fn set_mount_point(letter: char, volume: &str) -> Result<()> {
    const SLASH: char = '\\';
    let mount = nul_terminated(&format!("{letter}:{SLASH}"));
    let volume = nul_terminated(volume);
    let ok = unsafe { winapi::um::winbase::SetVolumeMountPointW(mount.as_ptr(), volume.as_ptr()) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("putting a volume on {letter}: {err}");
    }
    Ok(())
}

/// Ask Windows to look over its device tree again.
///
/// This is what the `Update-HostStorageCache` cmdlet does (`devcon rescan` and
/// Device Manager's "Scan for hardware changes" are the same call). A disk that has
/// just been logged into over iSCSI is a device without a disk behind it until a
/// scan happens, and on a machine that also has a security minifilter loaded that
/// scan can be slow enough that the wait loop would give up first. `DevInst` 0 is
/// the root of the tree, so this scans everything, not one branch.
pub(crate) fn rescan_devices() -> Result<()> {
    #[cfg(windows)]
    {
        let code = unsafe {
            winapi::um::cfgmgr32::CM_Reenumerate_DevNode(
                0,
                winapi::um::cfgmgr32::CM_REENUMERATE_NORMAL,
            )
        };
        if code != winapi::um::cfgmgr32::CR_SUCCESS {
            anyhow::bail!("Windows would not look over its devices again (code {code})");
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("rescanning devices is a Windows notion; there are none here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_has_a_word_for_the_user() {
        for state in [
            ServiceState::NotInstalled,
            ServiceState::Stopped,
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::Running,
            ServiceState::Paused,
            ServiceState::Unknown(99),
        ] {
            assert!(!state.word().is_empty());
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_state_codes_are_read() {
        assert_eq!(ServiceState::from_code(4), ServiceState::Running);
        assert_eq!(ServiceState::from_code(1), ServiceState::Stopped);
        assert_eq!(ServiceState::from_code(42), ServiceState::Unknown(42));
    }

    #[cfg(windows)]
    #[test]
    fn the_file_system_of_a_letter_is_read() {
        // The test runs from the repository, so `C:` is a real NTFS volume.
        let system = file_system('C').expect("C: has a file system");
        assert!(!system.is_empty());
        assert_eq!(file_system('?'), None, "?: is not a letter");
    }

    #[cfg(windows)]
    #[test]
    fn a_service_that_is_not_there_is_said_so() {
        // No elevation is needed to *ask*: `SC_MANAGER_CONNECT` is granted to users.
        assert_eq!(
            service_state("vcrs-there-is-no-such-service").unwrap(),
            ServiceState::NotInstalled
        );
        assert!(matches!(
            service_state("msiscsi").unwrap(),
            ServiceState::Running | ServiceState::Stopped | ServiceState::StartPending
        ));
    }
}

/// The storage side of the same effort: what `Get-Partition`/`Get-Disk` and
/// `Remove-PartitionAccessPath` answer, without a cmdlet import.
#[cfg(all(test, windows))]
mod volume_tests {
    use super::*;

    /// Every volume Windows lists, and the disk it says it is on.
    #[test]
    fn volumes_report_their_disk_on_a_real_machine() {
        let volume = volume_on_disk(0).expect("some volume is on disk 0");
        // The name Windows lists carries the device prefix and a trailing backslash, and
        // opening it needs the name without that backslash.
        assert!(volume.contains("Volume{"), "{volume:?}");
        assert!(volume.ends_with(char::from(92u8)), "{volume:?}");
        assert_eq!(volume_disk(&volume).ok(), Some(0));
    }

    #[test]
    fn the_volume_behind_a_letter_is_found() {
        // The tests run from the repository, so `C:` is a real volume on a real disk.
        let found = volume_of_letter('c').expect("C: is a volume");
        assert!(
            found.volume.contains("Volume{") && found.volume.ends_with('\\'),
            "a volume name looks like a GUID path, got {}",
            found.volume
        );
        assert_eq!(found.disk, 0, "the system volume is on disk 0");
    }

    #[test]
    fn something_that_is_not_a_letter_is_refused() {
        assert!(volume_of_letter('1').is_err());
        assert!(volume_of_letter(' ').is_err());
        assert!(release_letter('?').is_err());
    }

    #[test]
    fn a_letter_with_no_volume_is_not_found() {
        // `Q:` is not a volume on the machines this runs on, so naming it fails, and
        // taking it away is a success: there is nothing to take away.
        assert!(volume_of_letter('Q').is_err());
        assert!(release_letter('Q').is_ok());
    }
}
