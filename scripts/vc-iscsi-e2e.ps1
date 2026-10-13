# Elevated end-to-end acceptance test for the iSCSI ("option A") mount path:
#
#   vc-rs container -> vcrs mount --raw (iSCSI target) -> Microsoft Initiator
#   -> Windows formats NTFS on the disk -> files written by Windows
#   -> container detached -> real VeraCrypt mounts the SAME container and reads
#      those files back.
#
# Must run elevated (the Microsoft iSCSI Initiator needs admin; Dokany does not).
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait `
#     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<this file>'"
#
# Log: .logs/vc-iscsi-e2e.log (Tee-Object writes UTF-16LE; read it with
#      `iconv -f UTF-16LE -t UTF-8`).

$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Vcrs = Join-Path $Repo 'target\debug\vcrs.exe'
$VeraCrypt = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$Vol = Join-Path $Repo 'testdata\ours-iscsi.vc'
$Pw = 'PwIscsi'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
$Label = 'VCISCSI'
$Letter = 'S'
$VcLetter = 'Z'
$Big = Join-Path $Repo 'testdata\iscsi-big.bin'
$Log = Join-Path $Repo '.logs\vc-iscsi-e2e.log'
$Tag = '*VeraCrypt volume*'

$script:failures = @()
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
    # Windows refuses to log a session out while its disk is in use, so drop the
    # drive letters and take the disk offline first.
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
function Logout-Sessions($iqn) {
    # Log out our sessions; a stale session left behind by an earlier run keeps
    # Windows retrying a target that no longer exists, and the retry storm then
    # interferes with the PnP setup of the disk we actually want.
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
    if ($iqn) {
        $left = (cmd /c 'iscsicli SessionList 1 2>&1' | Out-String)
        if ($left -match [regex]::Escape($script:IqnPrefix)) {
            Say '  stale sessions remain - restarting msiscsi to clear them'
            Restart-Service msiscsi -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }
}
function Initiator-Instance {
    $out = cmd /c 'iscsicli ListInitiators 2>&1'
    foreach ($line in $out) { if ($line -match '^\s*(ROOT\\ISCSIPRT\\\S+)\s*$') { return $Matches[1] } }
    return 'Root\ISCSIPRT\0000_0'
}

Say "=== vc-rs iSCSI end-to-end test $(Get-Date -Format o) ==="
Say "elevated  : $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

# ---------------------------------------------------------------- 0. cleanup
Say '--- 0. cleanup'
Release-Disk
Logout-Sessions $Iqn
Remove-Target $Iqn
Stop-Target

# ------------------------------------------------------------ 1. the volume
Say '--- 1. create a fresh container (no filesystem inside)'
Remove-Item $Vol -Force -ErrorAction SilentlyContinue
& $Vcrs create $Vol -s 20M -p $Pw 2>&1 | ForEach-Object { Say "  $_" }
Check 'container-created' (Test-Path $Vol)

Say '--- 2. serve it as an iSCSI disk'
$script:proc = Start-Process -FilePath $Vcrs -ArgumentList @('mount', $Vol, '-p', $Pw, '--raw') `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $Repo '.logs\vcrs-iscsi.out') `
    -RedirectStandardError (Join-Path $Repo '.logs\vcrs-iscsi.err')
$listening = $false
for ($i = 0; $i -lt 30; $i++) {
    if (netstat -an | Select-String ':3260\s+.*LISTENING') { $listening = $true; break }
    Start-Sleep -Seconds 1
}
Check 'target-listening' $listening
if (-not $listening) { Stop-Target; Say 'FAILURES: target never listened'; exit 1 }

Say '--- 3. register the static target and log in'
# `AddTarget` registers the target+portal; `QLoginTarget` then performs the
# normal (non-discovery) login, which is the only path the iSCSI library
# supports with the Microsoft initiator.  The two empty strings must reach
# iscsicli as real empty arguments, which only happens through `cmd /c`.
cmd /c "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0" 2>&1 |
    ForEach-Object { Say "    $_" }
$login = cmd /c "iscsicli QLoginTarget $Iqn 2>&1"
$loginOk = ($login -join "`n") -match 'The operation completed successfully'
Check 'initiator-login' $loginOk
if (-not $loginOk) { $login | ForEach-Object { Say "    $_" }; Stop-Target; Say 'FAILURES: login'; exit 1 }

Say '--- 4. wait for the disk'
$disk = $null
for ($i = 0; $i -lt 30; $i++) {
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $disk = Vcrs-Disks | Select-Object -First 1
    if ($disk) { break }
    Start-Sleep -Seconds 1
}
Check 'disk-visible' ($null -ne $disk)
if (-not $disk) { Release-Disk; Logout-Sessions $Iqn; Stop-Target; Say 'FAILURES: no disk'; exit 1 }
Say "  disk $($disk.Number): $($disk.FriendlyName) $($disk.Size) bytes, $($disk.PartitionStyle)"
Check 'disk-mbr' ($disk.PartitionStyle -eq 'MBR')
# the disk is the data area plus the 1 MiB synthetic prefix that carries the MBR
$expectedDiskSize = [int64](Get-Item $Vol).Length - 262144 + 1048576
Say "  expected disk size: $expectedDiskSize bytes (data area + 1 MiB MBR prefix)"
Check 'disk-size-ok' ([int64]$disk.Size -eq $expectedDiskSize)

$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1MB } | Select-Object -First 1
Check 'partition-visible' ($null -ne $part)
Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
if ($part) {
    Say "  partition $($part.PartitionNumber): $($part.Size) bytes"
    Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $Letter -ErrorAction SilentlyContinue
}

Say '--- 5. format NTFS through the iSCSI disk'
Format-Volume -DriveLetter $Letter -FileSystem NTFS -NewFileSystemLabel $Label -Confirm:$false -Force -ErrorAction SilentlyContinue |
    Out-String | ForEach-Object { Say $_ }
$fs = Get-Volume -DriveLetter $Letter -ErrorAction SilentlyContinue
Check 'ntfs-volumesize' ($fs -and $fs.FileSystem -eq 'NTFS')
Check 'ntfs-label' ($fs -and $fs.FileSystemLabel -eq $Label)
if (-not $fs -or $fs.FileSystem -ne 'NTFS') {
    Release-Disk; Logout-Sessions $Iqn; Stop-Target; Say 'FAILURES: NTFS format'; exit 1
}

Say '--- 6. write files through the iSCSI disk'
Set-Content -Path "${Letter}:\from-windows.txt" -Value 'WINDOWS-WROTE-OVER-ISCSI' -NoNewline -Encoding Ascii
New-Item -ItemType Directory -Path "${Letter}:\sub" -Force | Out-Null
Set-Content -Path "${Letter}:\sub\nested.txt" -Value 'nested' -NoNewline -Encoding Ascii
if (-not (Test-Path $Big)) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] (1MB)
    $rng.GetBytes($buf)
    [IO.File]::WriteAllBytes($Big, $buf)
}
Copy-Item $Big "${Letter}:\big.bin" -Force
$srcHash = (Get-FileHash $Big -Algorithm SHA256).Hash
$dstHash = (Get-FileHash "${Letter}:\big.bin" -Algorithm SHA256).Hash
$txt = (Get-Content "${Letter}:\from-windows.txt" -Raw).Trim()
Check 'windows-wrote-txt' ($txt -eq 'WINDOWS-WROTE-OVER-ISCSI')
Check 'windows-big-file' ($srcHash -eq $dstHash)
Say "  sha256: $dstHash"

Say '--- 7. detach the disk'
Release-Disk
Logout-Sessions $Iqn
for ($i = 0; $i -lt 20 -and $script:proc -and -not $script:proc.HasExited; $i++) { Start-Sleep -Seconds 1 }
Check 'target-exited' ($script:proc -eq $null -or $script:proc.HasExited)
Stop-Target
Remove-Target $Iqn
Check 'disk-gone' ($null -eq (Vcrs-Disks | Select-Object -First 1))

Say '--- 8. real VeraCrypt mounts the same container'
& $VeraCrypt /volume $Vol /letter $VcLetter /password $Pw /quit /silent 2>&1 | ForEach-Object { Say "  $_" }
Check 'veracrypt-mounted' (Wait-Drive $VcLetter 30)
if (Test-Path "${VcLetter}:\from-windows.txt") {
    $back = (Get-Content "${VcLetter}:\from-windows.txt" -Raw).Trim()
    Check 'veracrypt-read-txt' ($back -eq 'WINDOWS-WROTE-OVER-ISCSI')
} else { Check 'veracrypt-read-txt' $false }
Check 'veracrypt-read-nested' (Test-Path "${VcLetter}:\sub\nested.txt")
if (Test-Path "${VcLetter}:\big.bin") {
    $backHash = (Get-FileHash "${VcLetter}:\big.bin" -Algorithm SHA256).Hash
    Check 'veracrypt-big-file' ($srcHash -eq $backHash)
} else { Check 'veracrypt-big-file' $false }

& $VeraCrypt /dismount $VcLetter /quit /silent 2>&1 | ForEach-Object { Say "  $_" }
Stop-Target

Say ''
if ($script:failures.Count -eq 0) { Say 'FAILURES: none'; Say 'RESULT  : ALL OK' }
else { Say "FAILURES: $($script:failures -join ', ')"; Say 'RESULT  : FAILED' }
