# The end-to-end iSCSI test: Windows must format NTFS *through* the vc-rs block
# device and the resulting files must be readable by real VeraCrypt (and vice
# versa). Run it ELEVATED:
#
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait `
#     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<this file>'"
#
# Log: .logs/vc-iscsi-test.log (Tee-Object writes UTF-16LE in PowerShell 5.1,
# so read it with `iconv -f UTF-16LE -t UTF-8`).

$ErrorActionPreference = 'Continue'
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Vcrs = Join-Path $Repo 'target\debug\vcrs.exe'
$VeraCrypt = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$Vol = Join-Path $Repo 'testdata\ours-iscsi.vc'
$Pw = 'PwIscsi'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
$Label = 'VCISCSI'
$Letter = 'S'
$VcLetter = 'Z'
$Log = Join-Path $Repo '.logs\vc-iscsi-test.log'
$Out = Join-Path $Repo '.logs\vcrs-iscsi.out'
$Err = Join-Path $Repo '.logs\vcrs-iscsi.err'
$Big = Join-Path $Repo 'testdata\iscsi-big.bin'

$failures = @()

function Say($message) {
    Write-Host $message
    $message | Tee-Object -FilePath $Log -Append | Out-Null
}

function Check($name, $ok) {
    Say ("{0,-22}: {1}" -f $name, $ok)
    if (-not $ok) { $script:failures += $name }
}

function Wait-Drive($drive, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${drive}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

# Whether the initiator already knows this static target.
function Target-Known($iqn) {
    $out = & iscsicli ListTargets 2>&1 | Out-String
    return $out.Contains($iqn)
}

# Register a *static* target. needed because the iscsi-target crate cannot answer
# the Microsoft initiator's multi-PDU login during a discovery session.
#
# PowerShell 5.1 silently drops empty-string arguments when invoking native
# commands, which makes iscsicli print its usage instead of adding the target, so
# the two CHAP fields are passed as the literal two-character string `""` (the C
# runtime then hands iscsicli a genuinely empty argument). The `--%` form is the
# fallback: stop-parsing passes the command line through verbatim.
function Add-StaticTarget($iqn) {
    Say "--- registering a static target for $iqn"
    & iscsicli AddTarget $iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 '""' '""' 0 0 2>&1 |
        ForEach-Object { Say "  $_" }
    & iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
    if (Target-Known $iqn) { return $true }

    Say "  (retrying with --% stop-parsing; the IQN below must match $iqn)"
    & iscsicli --% AddTarget iqn.2025-12.io.vcrs:ours-iscsi vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 "" "" 0 0 2>&1 |
        ForEach-Object { Say "  $_" }
    & iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
    return (Target-Known $iqn)
}

function Our-Disk {
    Get-Disk | Where-Object { $_.FriendlyName -like '*VeraCrypt*' -or $_.FriendlyName -like '*vc-rs*' }
}

# Stop the target this run started (so an early exit does not leave it behind).
function Stop-Target {
    if ($script:proc -and -not $script:proc.HasExited) {
        Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    Get-Process -Name vcrs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Say "=== vc-rs iSCSI end-to-end test ==="
Say ("elevated: " + ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator))

# ---------------------------------------------------------------- leftover state
Say "--- cleaning up leftovers"
& iscsicli QLogoutTarget $Iqn 2>&1 | Out-Null
& iscsicli QDeleteTarget $Iqn 2>&1 | Out-Null
Get-Process -Name vcrs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# ---------------------------------------------------------------- create + serve
Say "--- creating $Vol (20 MiB, quick format, no filesystem)"
Remove-Item -Force $Vol -ErrorAction SilentlyContinue
& $Vcrs create $Vol -s 20M -p $Pw 2>&1 | ForEach-Object { Say "  $_" }
if (-not (Test-Path $Vol)) { Say 'FATAL: the container was not created'; exit 1 }

Say "--- starting the iSCSI target"
$proc = Start-Process -FilePath $Vcrs -ArgumentList @('mount', $Vol, '-p', $Pw, '--raw') `
    -PassThru -NoNewWindow -RedirectStandardOutput $Out -RedirectStandardError $Err
Say ("  vcrs pid " + $proc.Id)

$listening = $false
for ($i = 0; $i -lt 30; $i++) {
    $conn = netstat -an | Select-String ':3260\s+.*LISTENING'
    if ($conn) { $listening = $true; break }
    Start-Sleep -Seconds 1
}
Check 'target-listening' $listening
if (-not $listening) { Get-Content $Out -ErrorAction SilentlyContinue | ForEach-Object { Say "  $_" }; Stop-Target; exit 1 }

# ---------------------------------------------------------------- initiator login
Say "--- ensuring the Microsoft iSCSI Initiator service is running"
$svc = Get-Service msiscsi -ErrorAction SilentlyContinue
if (-not $svc) { Say '  FATAL: the msiscsi service is missing'; Stop-Target; exit 1 }
if ($svc.Status -ne 'Running') {
    Say ("  starting msiscsi (was " + $svc.Status + ")")
    Start-Service msiscsi -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc = Get-Service msiscsi
}
Check 'initiator-service' ($svc.Status -eq 'Running')
if ($svc.Status -ne 'Running') { Stop-Target; exit 1 }

Say "--- logging in with the Microsoft iSCSI Initiator"
# A *static* target is registered instead of scanning a portal: the iscsi-target
# crate cannot complete the Microsoft initiator's multi-PDU login during a
# discovery session (see crates/vcrs-mount/src/iscsi.rs), while a static target
# logs in correctly.
$registered = Add-StaticTarget $Iqn
Check 'target-registered' $registered
if (-not $registered) {
    Say '  hint: the Microsoft initiator would also accept a discovered target, but the'
    Say '  iscsi-target crate cannot complete a discovery-session login (see iscsi.rs).'
    Stop-Target
    exit 1
}
& iscsicli QLoginTarget $Iqn 2>&1 | ForEach-Object { Say "  $_" }
Update-HostStorageCache
Start-Sleep -Seconds 3

$disk = $null
for ($i = 0; $i -lt 30; $i++) {
    $disk = Our-Disk | Select-Object -First 1
    if ($disk) { break }
    Update-HostStorageCache
    Start-Sleep -Seconds 1
}
Check 'disk-visible' ($null -ne $disk)
if (-not $disk) {
    Say '  disks seen:'
    Get-Disk | ForEach-Object { Say ("    " + $_.Number + ' ' + $_.FriendlyName) }
    & iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
    Stop-Target
    exit 1
}
$dn = $disk.Number
Say ("  disk {0}: {1} {2} bytes, partition style {3}" -f $dn, $disk.FriendlyName, $disk.Size, $disk.PartitionStyle)
Check 'disk-mbr' ($disk.PartitionStyle -eq 'MBR')
Check 'disk-size-ok' (($disk.Size - 20MB) -eq 1048576)   # data area + the 1 MiB synthetic prefix

# Windows must be able to read the synthetic MBR's partition table.
$part = Get-Partition -DiskNumber $dn -ErrorAction SilentlyContinue |
    Where-Object { $_.Size -gt 1MB } | Select-Object -First 1
Check 'partition-visible' ($null -ne $part)
Say ("  partitions: " + ((Get-Partition -DiskNumber $dn | ForEach-Object { "$($_.PartitionNumber):$($_.Size)" }) -join ', '))
if (-not $part) { Stop-Target; exit 1 }
$pn = $part.PartitionNumber

Set-Disk -Number $dn -IsOffline $false -ErrorAction SilentlyContinue
Set-Disk -Number $dn -IsReadOnly $false -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- format NTFS here
Say "--- assigning $Letter`: and formatting NTFS"
Set-Partition -DiskNumber $dn -PartitionNumber $pn -NewDriveLetter $Letter -ErrorAction SilentlyContinue
if (-not (Test-Path "${Letter}:\")) {
    Say "  Set-Partition did not take, trying diskpart"
    $script = "select disk $dn`r`nselect partition $pn`r`nassign letter=$Letter`r`nformat fs=ntfs quick label=$Label`r`nexit"
    $script | diskpart | ForEach-Object { Say "  $_" }
} else {
    Format-Volume -DriveLetter $Letter -FileSystem NTFS -NewFileSystemLabel $Label `
        -Confirm:$false -Force -ErrorAction Continue | Out-Null
}
Start-Sleep -Seconds 2
$formatted = Test-Path "${Letter}:\"
Check 'ntfs-formatted' $formatted
if ($formatted) {
    $volume = Get-Volume -DriveLetter $Letter -ErrorAction SilentlyContinue
    if ($volume) {
        Say ("  volume: {0} {1}, label {2}, {3} bytes free" -f $volume.FileSystemType, $volume.DriveLetter,
            $volume.FileSystemLabel, $volume.SizeRemaining)
        Check 'ntfs-filesystem' ($volume.FileSystemType -eq 'NTFS')
    }
}
if (-not $formatted) { Stop-Target; exit 1 }

# ---------------------------------------------------------------- write through it
Say "--- writing files through the iSCSI disk"
Set-Content -Path "${Letter}:\from-windows.txt" -Value 'WINDOWS-WROTE-OVER-ISCSI' -NoNewline -Encoding Ascii
New-Item -ItemType Directory -Force -Path "${Letter}:\sub" | Out-Null
Set-Content -Path "${Letter}:\sub\nested.txt" -Value 'nested' -NoNewline -Encoding Ascii
$bigBytes = New-Object byte[] 1048576
(new-object Random 20261213).NextBytes($bigBytes)
[IO.File]::WriteAllBytes($Big, $bigBytes)
Copy-Item $Big "${Letter}:\big.bin"
$bigHash = (Get-FileHash -Algorithm SHA256 $Big).Hash
$hashBack = (Get-FileHash -Algorithm SHA256 "${Letter}:\big.bin").Hash
Check 'windows-read-back' ((Get-Content "${Letter}:\from-windows.txt" -Raw) -eq 'WINDOWS-WROTE-OVER-ISCSI')
Check 'windows-big-file' ($bigHash -eq $hashBack)
Say ("  dir $Letter`:")
Get-ChildItem -Recurse "${Letter}:\" | ForEach-Object { Say ("    " + $_.FullName.Substring(3) + '  ' + $_.Length) }

# ---------------------------------------------------------------- detach
Say "--- detaching the disk"
Remove-PartitionAccessPath -DiskNumber $dn -PartitionNumber $pn -AccessPath "${Letter}:\" -ErrorAction SilentlyContinue
& iscsicli QLogoutTarget $Iqn 2>&1 | ForEach-Object { Say "  $_" }
for ($i = 0; $i -lt 20; $i++) {
    if ($proc.HasExited) { break }
    Start-Sleep -Seconds 1
}
Check 'target-exited' $proc.HasExited
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
& iscsicli QDeleteTarget $Iqn 2>&1 | Out-Null

# ---------------------------------------------------------------- VeraCrypt reads
Say "--- real VeraCrypt must read the NTFS filesystem vc-rs served"
& $VeraCrypt /volume $Vol /letter $VcLetter /password $Pw /quit /silent
$mounted = Wait-Drive $VcLetter 30
Check 'veracrypt-mounted' $mounted
if ($mounted) {
    $text = (Get-Content "${VcLetter}:\from-windows.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'veracrypt-read-txt' ($text -eq 'WINDOWS-WROTE-OVER-ISCSI')
    $nested = (Get-Content "${VcLetter}:\sub\nested.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'veracrypt-read-sub' ($nested -eq 'nested')
    $hashVc = (Get-FileHash -Algorithm SHA256 "${VcLetter}:\big.bin" -ErrorAction SilentlyContinue).Hash
    Check 'veracrypt-big-file' ($bigHash -eq $hashVc)
    $volume = Get-Volume -DriveLetter $VcLetter -ErrorAction SilentlyContinue
    if ($volume) { Say ("  volume: {0}, label {1}" -f $volume.FileSystemType, $volume.FileSystemLabel) }
    Say "  dir $VcLetter`:"
    Get-ChildItem -Recurse "${VcLetter}:\" -ErrorAction SilentlyContinue |
        ForEach-Object { Say ("    " + $_.FullName.Substring(3) + '  ' + $_.Length) }
}
& $VeraCrypt /dismount $VcLetter /quit /silent
Start-Sleep -Seconds 2

Get-Process -Name vcrs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Say ''
if ($failures.Count -eq 0) { Say 'FAILURES: none' } else { Say ("FAILURES: " + ($failures -join ', ')) }
if ($failures.Count -eq 0) { Say 'RESULT  : ALL OK' } else { Say 'RESULT  : FAILED' }
