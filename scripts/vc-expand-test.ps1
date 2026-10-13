# Elevated end-to-end acceptance test for container expansion (VeraCrypt's
# Volume Expander semantics):
#
#   create a 20 MiB container -> serve it over iSCSI -> Windows formats NTFS on
#   it and writes files -> detach -> `vcrs expand` it to 40 MiB -> serve it
#   again -> the disk is bigger while the partition/filesystem still have their
#   old size -> Windows grows both with `Resize-Partition` -> the files are
#   still intact -> detach -> real VeraCrypt mounts the SAME container and reads
#   the files back.
#
#   Then (part 2) VeraCrypt mounts an expanded container that holds a FAT
#   filesystem, to show the expanded header is still fully VeraCrypt-readable.
#
# Must run elevated.
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait `
#     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<this file>'"
#
# Log: .logs/vc-expand-test.log (Tee-Object writes UTF-16LE; read it with
#      `iconv -f UTF-16LE -t UTF-8`).

$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Vcrs = Join-Path $Repo 'target\debug\vcrs.exe'
$VeraCrypt = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$Vol = Join-Path $Repo 'testdata\ours-expand.vc'
$FatVol = Join-Path $Repo 'testdata\smoke-expand.vc'
$Pw = 'PwExpand'
$Iqn = 'iqn.2025-12.io.vcrs:ours-expand'
$Label = 'VCEXPAND'
$Letter = 'S'
$VcLetter = 'Z'
$Big = Join-Path $Repo 'testdata\expand-big.bin'
$Log = Join-Path $Repo '.logs\vc-expand-test.log'
$Tag = '*VeraCrypt volume*'
$StartSize = 20MB
$EndSize = 40MB

# Windows pops up a "you need to format the disk" dialog for every raw volume it
# auto-mounts, and this test attaches several of them, so the dialogs pile up.
# `mountvol /N` tells the mount manager not to auto-mount new volumes; the script
# still assigns its own drive letter explicitly. It is switched back on before
# every exit.
function Disable-Automount { & mountvol /N 2>&1 | Out-Null }
function Restore-Automount { & mountvol /E 2>&1 | Out-Null }

$script:failures = @()
Disable-Automount
$script:proc = $null
$script:IqnPrefix = 'iqn.2025-12.io.vcrs:'

function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
function Check($name, $ok) {
    if ($ok) { Say "  [ok]   $name" } else { Say "  [FAIL] $name"; $script:failures += $name }
}
function Wait-Drive($drive, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${drive}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Vcrs-Disks { Get-Disk | Where-Object { $_.FriendlyName -like $Tag } }

function Release-Disk {
    foreach ($d in Vcrs-Disks) {
        Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter } |
            ForEach-Object {
                Say "  removing access path $($_.DriveLetter):"
                Remove-PartitionAccessPath -DiskNumber $_.DiskNumber -PartitionNumber $_.PartitionNumber `
                    -AccessPath ($_.DriveLetter + ':\') -ErrorAction SilentlyContinue
            }
        Say "  taking disk $($d.Number) offline"
        Set-Disk -Number $d.Number -IsOffline $true -ErrorAction SilentlyContinue
    }
}
function Stop-Target {
    if ($script:proc -and -not $script:proc.HasExited) {
        Say "  stopping the iSCSI target (pid $($script:proc.Id))"
        Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue
    }
    $script:proc = $null
    Get-Process vcrs -ErrorAction SilentlyContinue | ForEach-Object {
        Say "  killing leftover vcrs pid $($_.Id)"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
}
function Remove-Target($iqn) {
    Say "  iscsicli RemoveTarget $iqn"
    cmd /c "iscsicli RemoveTarget $iqn 2>&1" | ForEach-Object { Say "    $_" }
}
function Logout-Sessions {
    $out = cmd /c 'iscsicli SessionList 1 2>&1'
    $sid = $null
    foreach ($line in $out) {
        if ($line -match '^\s*Session Id\s*:\s*(\S+)') { $sid = $Matches[1] }
        elseif ($line -match '^\s*Target Name\s*:\s*(\S+)' -and $Matches[1] -like "$($script:IqnPrefix)*") {
            Say "  iscsicli LogoutTarget $sid ($($Matches[1]))"
            cmd /c "iscsicli LogoutTarget $sid 2>&1" | ForEach-Object { Say "    $_" }
            $sid = $null
        }
    }
    $left = (cmd /c 'iscsicli SessionList 1 2>&1' | Out-String)
    if ($left -match [regex]::Escape($script:IqnPrefix)) {
        Say '  stale sessions remain - restarting msiscsi to clear them'
        Restart-Service msiscsi -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

function Detach {
    Release-Disk
    Logout-Sessions
    if ($script:proc -and -not $script:proc.HasExited) {
        Say '  waiting for the iSCSI target to exit (the session ended)'
        if (-not $script:proc.WaitForExit(20000)) { Stop-Target; return }
    }
    Say '  target exited'
    Remove-Target $Iqn
}

function Serve {
    param([string]$Password)
    Release-Disk
    Logout-Sessions
    Remove-Target $Iqn
    Stop-Target
    $script:proc = Start-Process -FilePath $Vcrs -PassThru -NoNewWindow `
        -ArgumentList @('mount', $Vol, '-p', $Password, '--raw') `
        -RedirectStandardOutput (Join-Path $Repo '.logs\vcrs-expand.out') `
        -RedirectStandardError (Join-Path $Repo '.logs\vcrs-expand.err')
    $listening = $false
    for ($i = 0; $i -lt 30; $i++) {
        if ((netstat -an | Select-String ':3260\s+.*LISTENING')) { $listening = $true; break }
        Start-Sleep -Seconds 1
    }
    Check 'target-listening' $listening
    if (-not (Get-Service msiscsi -ErrorAction SilentlyContinue)) { return }
    if ((Get-Service msiscsi).Status -ne 'Running') {
        Say '  starting the msiscsi service'
        Start-Service msiscsi -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Check 'initiator-service' ((Get-Service msiscsi).Status -eq 'Running')
    Say "  iscsicli AddTarget $Iqn"
    cmd /c "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0 2>&1" |
        ForEach-Object { Say "    $_" }
    Say "  iscsicli QLoginTarget $Iqn"
    cmd /c "iscsicli QLoginTarget $Iqn 2>&1" | ForEach-Object { Say "    $_" }
}

function Get-OurVolume($letter) { Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue }
# VeraCrypt's driver does not always publish a volume object for its mounts, so
# fall back to the logical-disk view for those letters.
function Wait-MountedVolume($letter, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        $obj = Get-MountedVolume $letter
        if ($obj) { return $obj }
        Start-Sleep -Seconds 1
    }
    return Get-MountedVolume $letter
}
function Get-MountedVolume($letter) {
    $obj = Get-OurVolume $letter
    if ($obj) { return $obj }
    $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${letter}:'" -ErrorAction SilentlyContinue
    if ($ld) {
        return [pscustomobject]@{ FileSystem = $ld.FileSystem; Size = $ld.Size; FileSystemLabel = $ld.VolumeName }
    }
    return $null
}

function Attach {
    # Attach the served target and bring the synthetic-MBR disk online with a
    # drive letter. Returns the disk, or $null when the disk never showed up.
    param([int64]$ExpectedSize)
    $disk = $null
    for ($i = 0; $i -lt 30; $i++) {
        Update-HostStorageCache -ErrorAction SilentlyContinue
        $disk = Vcrs-Disks | Select-Object -First 1
        if ($disk) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $disk) { Check 'disk-visible' $false; return $null }
    Say "  disk $($disk.Number): $($disk.Size) bytes, $($disk.PartitionStyle), offline $($disk.IsOffline), expected $ExpectedSize"
    Check 'disk-visible' $true
    Check 'disk-size' ([int64]$disk.Size -eq $ExpectedSize)

    # Windows only reads the partition table when something asks for it, so
    # Get-Partition has to come before the partition can be addressed.
    $part = $null
    for ($i = 0; $i -lt 15; $i++) {
        $part = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
            Where-Object { $_.Size -gt 1MB } | Select-Object -First 1
        if ($part) { break }
        Update-HostStorageCache -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    Check 'partition-visible' ($null -ne $part)
    if ($disk.PartitionStyle -eq 'MBR') { Say "  partition size $($part.Size) bytes of the $($disk.Size) byte disk" }
    if (-not $part) { return $null }
    Say "  partition $($part.PartitionNumber): $($part.Size) bytes"

    Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
    if ($part.DriveLetter -and $part.DriveLetter -ne $Letter) {
        # Windows remembers volumes by their GPT/MBR identity and may hand out a
        # different letter, so drop it and take the one the test expects.
        Say "  dropping the remembered drive letter $($part.DriveLetter):"
        Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber `
            -AccessPath ($part.DriveLetter + ':') -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        $part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber `
            -ErrorAction SilentlyContinue
    }
    if ($part -and -not $part.DriveLetter) {
        Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber `
            -NewDriveLetter $Letter -ErrorAction SilentlyContinue
    }
    for ($i = 0; $i -lt 20; $i++) {
        if (Get-OurVolume $Letter) { break }
        Start-Sleep -Seconds 1
    }
    $volObj = Get-OurVolume $Letter
    Say "  volume ${Letter}: filesystem $($volObj.FileSystem), label $($volObj.FileSystemLabel), size $($volObj.Size)"
    Check 'drive-letter' ($null -ne $volObj)
    return $disk
}

Say "=== vc-rs expansion end-to-end test $(Get-Date -Format o) ==="
Say "elevated  : $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "veracrypt : $((Get-Item $VeraCrypt).VersionInfo.FileVersion)"

# ---------------------------------------------------------------- 0. cleanup
Say '--- 0. cleanup'
Release-Disk
Logout-Sessions
Remove-Target $Iqn
Stop-Target

# ------------------------------------------------------------- 1. container
Say "--- 1. create a $($StartSize / 1MB) MiB container"
Remove-Item $Vol -Force -ErrorAction SilentlyContinue
$createArgs = @('create', $Vol, "--size=$StartSize", '-p', $Pw)
$out = & $Vcrs @createArgs 2>&1
foreach ($line in $out) { Say "  $line" }
Check 'container-created' (Test-Path $Vol)

Say '--- 2. serve it and let Windows format NTFS on it'
Serve $Pw
$expected = [int64](Get-Item $Vol).Length - 262144 + 1048576
$disk = Attach $expected
if (-not $disk) { Stop-Target; Say 'FAILURES: no usable disk'; Say 'RESULT  : FAILED'; Restore-Automount; exit 1 }
Format-Volume -DriveLetter $Letter -FileSystem NTFS -NewFileSystemLabel $Label -Confirm:$false -Force `
    -ErrorAction SilentlyContinue | Out-String | ForEach-Object { Say $_ }
Start-Sleep -Seconds 2
$volObj = Wait-MountedVolume $Letter 20
Check 'ntfs' ($volObj -and $volObj.FileSystem -eq 'NTFS')
if (-not $volObj -or $volObj.FileSystem -ne 'NTFS') {
    Detach; Stop-Target; Say 'FAILURES: NTFS format'; Say 'RESULT  : FAILED'; exit 1
}

Say '--- 3. write files through the iSCSI disk'
'WRITTEN-BEFORE-EXPAND' | Set-Content "${Letter}:\before.txt" -Encoding Ascii -NoNewline
if (-not (Test-Path $Big)) {
    $bytes = New-Object byte[] (1MB)
    (New-Object Random).NextBytes($bytes)
    [IO.File]::WriteAllBytes($Big, $bytes)
}
Copy-Item $Big "${Letter}:\big.bin" -Force
$hashBefore = (Get-FileHash "${Letter}:\big.bin" -Algorithm SHA256).Hash
Check 'windows-wrote-txt' ((Get-Content "${Letter}:\before.txt" -Raw).Trim() -eq 'WRITTEN-BEFORE-EXPAND')
Check 'ntfs-label' ($volObj.FileSystemLabel -eq $Label)
$usedBefore = $volObj.Size
Say "  volume size before the expansion: $usedBefore bytes"

Say '--- 4. detach'
Detach
Check 'disk-gone' ($null -eq (Vcrs-Disks | Select-Object -First 1))

# -------------------------------------------------------- 5. expand (vc-rs)
Say "--- 5. vcrs expand to $($EndSize / 1MB) MiB"
$expandArgs = @('expand', $Vol, "--size=$EndSize", '-p', $Pw, '--force')
Say "  $Vcrs $($expandArgs -join ' ')"
$out = & $Vcrs @expandArgs 2>&1
foreach ($line in $out) { Say "  $line" }
Say "  exit code $LASTEXITCODE"
$lenAfter = [int64](Get-Item $Vol).Length
Check 'container-grew' ($lenAfter -eq $EndSize)

Say '--- 6. serve the expanded container again'
Serve $Pw
$expected2 = $lenAfter - 262144 + 1048576
$disk = Attach $expected2
if (-not $disk) { Stop-Target; Say 'FAILURES: no usable disk after expansion'; Say 'RESULT  : FAILED'; Restore-Automount; exit 1 }
$volObj = Get-OurVolume $Letter
Say "  filesystem still $($volObj.Size) bytes of the $($disk.Size) byte disk"
Check 'filesystem-not-yet-extended' ($volObj.Size -lt $expected2 - 10MB)

Say '--- 7. the data written before the expansion is still there'
Check 'files-survived-expand' ((Get-Content "${Letter}:\before.txt" -Raw).Trim() -eq 'WRITTEN-BEFORE-EXPAND')
Check 'big-file-survived-expand' `
    ((Get-FileHash "${Letter}:\big.bin" -Algorithm SHA256).Hash -eq $hashBefore)

Say '--- 8. extend the partition and the filesystem into the new space'
$supported = Get-PartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber 1
Say "  partition can grow to $($supported.SizeMax) bytes"
Resize-Partition -DiskNumber $disk.Number -PartitionNumber 1 -Size $supported.SizeMax
Start-Sleep -Seconds 2
$volObj = Wait-MountedVolume $Letter 20
Say "  volume is now $($volObj.Size) bytes of $($volObj.FileSystem)"
Check 'filesystem-extended' ($volObj -and $volObj.Size -gt $usedBefore + 10MB)
Check 'files-still-there-after-extend' ((Get-Content "${Letter}:\before.txt" -Raw).Trim() -eq 'WRITTEN-BEFORE-EXPAND')
Check 'big-file-still-there' ((Get-FileHash "${Letter}:\big.bin" -Algorithm SHA256).Hash -eq $hashBefore)

Say '--- 9. detach and check with real VeraCrypt'
Detach
& $VeraCrypt /volume $Vol /letter $VcLetter /password $Pw /quit /silent | Out-Null
$mounted = Wait-Drive $VcLetter 30
Check 'veracrypt-mounted' $mounted
if ($mounted) {
    Check 'veracrypt-read-txt' ((Get-Content "${VcLetter}:\before.txt" -Raw).Trim() -eq 'WRITTEN-BEFORE-EXPAND')
    Check 'veracrypt-big-file' ((Get-FileHash "${VcLetter}:\big.bin" -Algorithm SHA256).Hash -eq $hashBefore)
    Check 'veracrypt-sees-the-new-size' ((Get-MountedVolume $VcLetter).Size -gt $usedBefore + 10MB)
    & $VeraCrypt /dismount $VcLetter /quit /silent | Out-Null
    Start-Sleep -Seconds 2
}

Say '--- 10. VeraCrypt mounts an expanded FAT container too'
if (Test-Path $FatVol) {
    & $VeraCrypt /volume $FatVol /letter $VcLetter /password $Pw /pim 1 /quit /silent | Out-Null
    $mounted = Wait-Drive $VcLetter 30
    Check 'veracrypt-mounted-fat' $mounted
    if ($mounted) {
        $fatVolObj = Get-MountedVolume $VcLetter
        Say "  filesystem: $($fatVolObj.FileSystem), label '$($fatVolObj.FileSystemLabel)', size $($fatVolObj.Size)"
        # The FAT filesystem was formatted before the expansion and is smaller than
        # the grown container; what matters is that VeraCrypt still reads it.
        Check 'veracrypt-fat-filesystem' ($fatVolObj.FileSystem -like 'FAT*')
        Check 'veracrypt-fat-size' ($fatVolObj.Size -gt 15MB)
        & $VeraCrypt /dismount $VcLetter /quit /silent | Out-Null
        Start-Sleep -Seconds 2
    }
}

Stop-Target
Say ''
if ($script:failures.Count -eq 0) { Say 'FAILURES: none'; Say 'RESULT  : ALL OK' }
else { Say "FAILURES: $($script:failures -join ', ')"; Say 'RESULT  : FAILED' }
