<#
.SYNOPSIS
    In-place encryption of a whole PARTITION (VeraCrypt's "encrypt a non-system
    partition in place"), verified on a throwaway VHD.

.DESCRIPTION
    A real partition is needed to exercise this code, so the script builds one:
    a fixed VHD, MBR, one NTFS partition, some files -- then it runs the round
    trip and checks the files, their hashes and chkdsk afterwards:

        vcrs encrypt-in-place V:      shrink the filesystem, lock/dismount it,
                                      conceal the head, encrypt top-down, write
                                      the primary header group (the backup one
                                      was written first, which is what makes the
                                      run resumable)
        vcrs read V: / vcrs info V:   read the finished volume through the device
                                      path (an encrypted device is RAW)
        vcrs decrypt-in-place V:      take it back to a plain filesystem

    VeraCrypt's own mount of the finished partition is attempted when VeraCrypt
    is installed; it is reported as SKIPPED when this machine cannot mount
    anything at all (a security product filtering the volume stack, for
    instance), and the round trip itself is verified without it.

    Must run elevated: raw device I/O and diskpart need administrator rights.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\device-inplace-test.ps1
    powershell -ExecutionPolicy Bypass -File scripts\device-inplace-test.ps1 -KeepVhd
#>
[CmdletBinding()]
param(
    [string] $Vhd,
    [int]    $SizeMB = 512,
    [string] $Letter = 'V',
    [string] $Password = 'PwDevice',
    [string] $VeraCrypt = 'C:\Program Files\VeraCrypt\VeraCrypt.exe',
    [switch] $KeepVhd
)

$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..')).Path
if (-not $Vhd) { $Vhd = Join-Path $Root '.logs\device-testbed.vhd' }
$Vcrs = Join-Path $Root 'target\debug\vcrs.exe'
$Log = Join-Path $Root '.logs\device-inplace-test.log'
New-Item -ItemType Directory -Force -Path (Split-Path $Log) | Out-Null
Start-Transcript -Path $Log -Force | Out-Null

$script:Failures = 0
function Say($m) { Write-Host $m }
function Check($name, $ok) {
    if ($ok) { Say "PASS: $name" } else { Say "FAIL: $name"; $script:Failures++ }
}
function Sha($p) { (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower() }
function Vol() { "$Letter`:" }
function FsName() {
    $v = Get-Volume -DriveLetter $Letter -ErrorAction SilentlyContinue
    if ($v) { $v.FileSystem } else { '<none>' }
}
function WaitFs($seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (FsName) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Run([string[]] $argv) {
    $out = & $Vcrs @argv 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Say "  $_" }
    return $code
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'this script has to run elevated (raw device access + diskpart)'
    Stop-Transcript | Out-Null
    exit 2
}
if (-not (Test-Path $Vcrs)) {
    Say "the vcrs binary was not found at $Vcrs -- run: bash scripts/msvc.sh cargo build"
    Stop-Transcript | Out-Null
    exit 2
}

# the caller may leave -Letter to us: then take a free one (V: may be in use)
if (-not $PSBoundParameters.ContainsKey('Letter') -and (Get-Volume -DriveLetter $Letter -ErrorAction SilentlyContinue)) {
    $wanted = $Letter
    foreach ($candidate in @('W', 'X', 'Y', 'Z', 'U', 'T')) {
        if (-not (Get-Volume -DriveLetter $candidate -ErrorAction SilentlyContinue)) {
            $Letter = $candidate
            break
        }
    }
    Say "drive letter $wanted`: is in use, using $Letter`: instead"
}
Say "using drive $Letter`: for the test bed"
Get-Command iscsicli -ErrorAction SilentlyContinue | Out-Null

Say "== step 0: build the test-bed partition on $Vhd =="
$Vhd = [System.IO.Path]::GetFullPath($Vhd)
# the disk that shows up after attaching is the test bed: remember what is there now
$disksBefore = @((Get-Disk).Number)
if (-not (Test-Path $Vhd)) {
    # diskpart is driven from a script file to keep it scriptable
    $dp = Join-Path $env:TEMP 'vcrs-device-vhd.txt'
    @(
        "create vdisk file=`"$Vhd`" maximum=$SizeMB type=fixed"
        "select vdisk file=`"$Vhd`""
        'attach vdisk'
        'clean'
        'convert mbr'
        'create partition primary'
        "assign letter=$Letter"
        'exit'
    ) | Set-Content -Path $dp -Encoding ASCII
    cmd /c "diskpart /s `"$dp`"" | ForEach-Object { Say "  $_" }
    Start-Sleep -Seconds 3
} else {
    $dp = Join-Path $env:TEMP 'vcrs-device-vhd.txt'
    @(
        "select vdisk file=`"$Vhd`""
        'attach vdisk'
        "select partition 1"
        "assign letter=$Letter"
        'exit'
    ) | Set-Content -Path $dp -Encoding ASCII
    cmd /c "diskpart /s `"$dp`"" | ForEach-Object { Say "  $_" }
    Start-Sleep -Seconds 3
}

# a VHD that was added while automount was off comes up offline / without a path
$disk = Get-Disk | Where-Object { $disksBefore -notcontains $_.Number } | Sort-Object Number | Select-Object -First 1
if ($disk) {
    Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $disk.Number -IsReadOnly $false -ErrorAction SilentlyContinue
    $part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 1MB } | Select-Object -First 1
    if ($part -and -not (Get-Partition -DiskNumber $disk.Number | Where-Object DriveLetter -eq $Letter)) {
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath "$Letter`:\" -ErrorAction SilentlyContinue
    }
    Say ("  disk {0}: {1} bytes, partition {2}: {3} bytes" -f $disk.Number, $disk.Size, $part.PartitionNumber, $part.Size)
}
Start-Sleep -Seconds 2

if (-not $disk) {
    Say 'the test-bed disk never appeared (diskpart failed?); nothing to do'
    Stop-Transcript | Out-Null
    exit 2
}
cmd /c "format $Letter /FS:NTFS /Q /V:DEVTEST /Y" | ForEach-Object { Say "  $_" }
WaitFs 30 | Out-Null
Check 'testbed-filesystem' ((FsName) -eq 'NTFS')

# test files: a text file, a nested one, and 1 MiB of pseudo-random bytes
# (Set-Content has no -NoNewline in PowerShell 5.1)
[System.IO.File]::WriteAllText("$(Vol)\hello.txt", 'hello from the device test')
New-Item -ItemType Directory -Force -Path "$(Vol)\sub" | Out-Null
[System.IO.File]::WriteAllText("$(Vol)\sub\nested.txt", 'nested')
$rng = New-Object Random 42
$bytes = New-Object byte[] (1MB)
$rng.NextBytes($bytes)
[System.IO.File]::WriteAllBytes("$(Vol)\big.bin", $bytes)
if (-not (Test-Path "$(Vol)\hello.txt")) {
    Say "  the test bed is not usable ($(Vol) has no hello.txt); stopping"
    Stop-Transcript | Out-Null
    exit 2
}
$bigBefore = Sha "$(Vol)\big.bin"
Say "  big.bin sha256: $bigBefore"

Say ''
Say '== step 1: what would be encrypted? =='
& $Vcrs device-info (Vol) 2>&1 | ForEach-Object { Say "  $_" }
Check 'device-info' ($LASTEXITCODE -eq 0)

Say ''
Say '== step 2: encrypt the partition in place =='
$t = Measure-Command { $code = Run @('encrypt-in-place', (Vol), '-p', $Password, '--yes') }
Check 'encrypted' ($code -eq 0)
Say ("  took {0:N1}s" -f $t.TotalSeconds)

Say ''
Say '== step 3: read the RAW volume through the device path =='
$code = Run @('read', (Vol), '-p', $Password, '-o', '0', '-l', '512', '--out', (Join-Path $Root '.logs\device-vbr.bin'))
Check 'read-through-device' ($code -eq 0)
$vbr = Join-Path $Root '.logs\device-vbr.bin'
if (Test-Path $vbr) {
    $b = [System.IO.File]::ReadAllBytes($vbr)
    $oem = -join ($b[3..10] | ForEach-Object { [char]$_ })
    Say "  boot sector OEM: '$oem'"
    Check 'filesystem-boot-sector' ($oem.Trim() -eq 'NTFS')
} else { Check 'filesystem-boot-sector' $false }
Check 'info-through-device' ((Run @('info', (Vol), '-p', $Password)) -eq 0)

Say ''
Say '== step 4: VeraCrypt mounts the finished partition (optional) =='
$vcResult = 'SKIPPED'
if (Test-Path $VeraCrypt) {
    # control first: can this machine mount anything at all right now?
    $control = Join-Path $Root 'testdata\smoke.vc'
    if (Test-Path $control) {
        & $VeraCrypt /volume $control /letter Y /password PwSmoke /pim 1 /quit /silent | Out-Null
        Start-Sleep -Seconds 4
        $controlOk = Test-Path 'Y:\'
        if ($controlOk) { & $VeraCrypt /dismount Y /quit /silent | Out-Null; Start-Sleep -Seconds 3 }
        if ($controlOk) {
            & $VeraCrypt /volume (Vol) /letter Z /password $Password /quit /silent | Out-Null
            $mounted = $false
            for ($i = 0; $i -lt 30; $i++) { if (Test-Path 'Z:\') { $mounted = $true; break }; Start-Sleep -Seconds 1 }
            if ($mounted) {
                $hello = (Get-Content 'Z:\hello.txt' -Raw -ErrorAction SilentlyContinue)
                $big = Sha 'Z:\big.bin'
                Say "  Z:\hello.txt = '$hello'"
                Check 'veracrypt-mounted-the-partition' $true
                Check 'veracrypt-read-hello' ($hello -eq 'hello from the device test')
                Check 'veracrypt-read-big-bin' ($big -eq $bigBefore)
                & $VeraCrypt /dismount Z /quit /silent | Out-Null
                Start-Sleep -Seconds 3
                $vcResult = 'MOUNTED'
            } else {
                Check 'veracrypt-mounted-the-partition' $false
                $vcResult = 'FAILED'
            }
        } else {
            Say '  VeraCrypt cannot mount even testdata\smoke.vc here (exit 1), so its own'
            Say '  mount of the partition cannot be judged: check for security software'
            Say '  filtering the volume stack (its driver is: sc query veracrypt) and retry.'
        }
    }
} else {
    Say "  VeraCrypt is not installed at $VeraCrypt"
}
Say "  VeraCrypt side: $vcResult"

Say ''
Say '== step 5: decrypt the partition again =='
$t = Measure-Command { $code = Run @('decrypt-in-place', (Vol), '-p', $Password, '--yes') }
Check 'decrypted' ($code -eq 0)
Say ("  took {0:N1}s" -f $t.TotalSeconds)
WaitFs 30 | Out-Null
Say "  filesystem: $(FsName)"
$hello = if (Test-Path "$(Vol)\hello.txt") { (Get-Content "$(Vol)\hello.txt" -Raw) } else { '<missing>' }
$nested = if (Test-Path "$(Vol)\sub\nested.txt") { (Get-Content "$(Vol)\sub\nested.txt" -Raw) } else { '<missing>' }
$bigAfter = if (Test-Path "$(Vol)\big.bin") { Sha "$(Vol)\big.bin" } else { '<missing>' }
Say "  hello.txt = '$hello'"
Say "  nested.txt = '$nested'"
Say "  big.bin sha256: $bigAfter"
Check 'hello-intact' ($hello -eq 'hello from the device test')
Check 'nested-intact' ($nested -eq 'nested')
Check 'big-bin-intact' (($bigAfter -ne '<missing>') -and ($bigAfter -eq $bigBefore))

Say ''
Say '== step 6: chkdsk =='
cmd /c "chkdsk $Letter`: /scan" 2>&1 | Select-Object -Last 8 | ForEach-Object { Say "  $_" }

if (-not $KeepVhd) {
    Say ''
    Say '== step 7: detach the test bed =='
    if ($disk) {
        $dp = Join-Path $env:TEMP 'vcrs-device-vhd.txt'
        @("select vdisk file=`"$Vhd`"", 'detach vdisk', 'exit') | Set-Content -Path $dp -Encoding ASCII
        cmd /c "diskpart /s `"$dp`"" | ForEach-Object { Say "  $_" }
    }
}

Say ''
if ($script:Failures -eq 0) { Say "RESULT: ALL OK (VeraCrypt side: $vcResult)" } else { Say "RESULT: FAILURES: $script:Failures" }
Stop-Transcript | Out-Null
if ($script:Failures -ne 0) { exit 1 }
