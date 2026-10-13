# Sector-size interoperability test (must run elevated: VeraCrypt needs admin).
#
# testdata/sec4k.vc is prepared beforehand (non-elevated):
#   vcrs create testdata/sec4k.vc --size 12M --password Pw4k --quick --sector-size 4096
#
# A volume sector size of 4096 means the filesystem inside must be formatted with 4096-byte
# sectors as well -- Windows refuses to mount a 512-sector FAT image on a 4096-sector
# device (that was the first thing this script caught).  So the test lets VeraCrypt present
# the volume to Windows and Windows format it, which is exactly what a user does, and then
# checks the boot sector that landed inside the container.

$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\yuan\Desktop\vc-rs'
$vcrs = Join-Path $repo 'target\debug\vcrs.exe'
$vc   = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$td   = Join-Path $repo 'testdata'
$logs = Join-Path $repo '.logs'
$log  = Join-Path $logs 'vc-sector-size-test.log'
$vol  = Join-Path $td 'sec4k.vc'
$pw   = 'Pw4k'
$letter = 'Z'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

$failures = 0
function Say($m) { $m | Tee-Object -FilePath $log -Append | Out-Null; Write-Host $m }
function Check($name, $ok) {
    if ($ok) { Say ("PASS  {0}" -f $name) } else { Say ("FAIL  {0}" -f $name); $script:failures++ }
}
function Run($exe, [string[]]$argv) {
    Say "> $exe $($argv -join ' ')"
    & $exe @argv 2>&1 | ForEach-Object { Say "  $_" }
    Say "  exit=$LASTEXITCODE"
}
function WaitDrive($letter, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${letter}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

Say "=== vc-rs sector size test $(Get-Date -Format s) ==="

# A mounted but unformatted volume has no drive *directory* to test, so look for the
# volume object itself (VeraCrypt's mount also does not always show up in Get-Volume,
# hence the Win32_LogicalDisk fallback).
function WaitVolume($letter, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue) { return $true }
        if (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Say "elevated  : $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "veracrypt : $((Get-Item $vc).VersionInfo.FileVersion)"
if (-not (Test-Path $vol)) { Say "!! $vol is missing"; exit 1 }
Run $vc @('/dismount', $letter, '/quit', '/silent') | Out-Null

Say ""
Say "1. The container records the 4096 byte sector size"
$header = & $vcrs info $vol --password $pw 2>&1 | Out-String
Check 'header-says-4096' ($header -match 'sector size\s+4096')

Say ""
Say "2. VeraCrypt mounts it"
Run $vc @('/volume', $vol, '/letter', $letter, '/password', $pw, '/quit', '/silent')
$mounted = WaitVolume $letter 30
Check 'veracrypt-mounted' $mounted
if (-not $mounted) {
    Say "RESULT: FAILURES: $failures"
    exit 1
}

Say ""
Say "3. Windows formats the volume (with the sector size VeraCrypt reports, i.e. 4096)"
format.com "${letter}:" /FS:NTFS /Q /V:VC4K /Y | ForEach-Object { Say "  $_" }
# Get-Volume does not list VeraCrypt's volumes reliably, so ask the WMI disk list.
$disk = $null
for ($i = 0; $i -lt 20; $i++) {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue
    if ($disk -and $disk.FileSystem) { break }
    Start-Sleep -Seconds 1
}
Say "  file system: $($disk.FileSystem), label $($disk.VolumeName), free $($disk.FreeSpace)"
Check 'windows-formatted' ($disk.FileSystem -eq 'NTFS')
Check 'label' ($disk.VolumeName -eq 'VC4K')

Say ""
Say "4. Windows writes through the mount and the write survives a remount"
Set-Content -Path "${letter}:\from-windows-4k.txt" -Value 'WROTE-ON-A-4K-SECTOR-VOLUME' -NoNewline
Check 'windows-wrote' (((Get-Content "${letter}:\from-windows-4k.txt" -Raw).Trim()) -eq 'WROTE-ON-A-4K-SECTOR-VOLUME')
Run $vc @('/dismount', $letter, '/quit', '/silent')
Run $vc @('/volume', $vol, '/letter', $letter, '/password', $pw, '/quit', '/silent')
Start-Sleep -Seconds 4
$back = (Get-Content "${letter}:\from-windows-4k.txt" -Raw).Trim()
Check 'file-survived-remount' ($back -eq 'WROTE-ON-A-4K-SECTOR-VOLUME')
Run $vc @('/dismount', $letter, '/quit', '/silent')

Say ""
Say "5. vc-rs decrypts the data area and sees the NTFS on-disk boot sector"
$boot = Join-Path $logs 'vbr-4k.bin'
Run $vcrs @('read', $vol, '--password', $pw, '--offset', '0', '--length', '512', '--out', $boot)
$bytes = [IO.File]::ReadAllBytes($boot)
$oem = [Text.Encoding]::ASCII.GetString($bytes, 3, 8)
$bytesPerSector = [int]$bytes[11] + ([int]$bytes[12] * 256)
Say "  OEM '$oem', bytes per sector $bytesPerSector"
Check 'ntfs-in-the-container' ($oem -eq 'NTFS    ')
Check 'filesystem-formed-with-4096-sectors' ($bytesPerSector -eq 4096)

Say ""
Say "6. The backup header carries the sector size too"
$backup = & $vcrs info $vol --password $pw --backup 2>&1 | Out-String
Check 'backup-header-says-4096' ($backup -match 'sector size\s+4096')

Say ""
if ($failures -eq 0) { Say "RESULT: ALL OK" } else { Say "RESULT: FAILURES: $failures" }
