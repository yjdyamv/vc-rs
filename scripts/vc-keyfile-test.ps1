# Elevated cross-check of keyfile support: real VeraCrypt mounts containers that
# were created with a keyfile, and reads a file out of a vc-rs-made keyfile
# container.  VeraCrypt mounts through its kernel driver, so this needs admin.
#
# Run:  powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\yuan\Desktop\vc-rs\scripts\vc-keyfile-test.ps1'"

param(
    [string]$Key = 'C:\Users\yuan\Desktop\vc-rs\testdata\keyfile.bin'
)

$Repo      = 'C:\Users\yuan\Desktop\vc-rs'
$VeraCrypt = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$Log       = Join-Path $Repo '.logs\vc-keyfile-test.log'
$script:failures = @()

function Say($msg) {
    Write-Host $msg
    $msg | Tee-Object -FilePath $Log -Append | Out-Null
}
function Check($name, $ok) {
    Say ("  {0,-32} {1}" -f $name, $ok)
    if (-not $ok) { $script:failures += $name }
}
function Wait-Drive($drive, $seconds = 15) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "$drive\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Wait-Volume($drive, $seconds = 15) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Get-Volume -DriveLetter $drive -ErrorAction SilentlyContinue) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
# Get-Volume does not always list a VeraCrypt-mounted volume, so ask the Win32
# logical-disk view (which does) for the filesystem name.
function Wait-FileSystem($drive, $seconds = 15) {
    for ($i = 0; $i -lt $seconds; $i++) {
        $fs = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction SilentlyContinue).FileSystem
        if ($fs) { return $fs }
        Start-Sleep -Seconds 1
    }
    return ''
}
function Dismount-Everything {
    foreach ($letter in 'Y', 'Z', 'W', 'V', 'X') {
        & $VeraCrypt /dismount $letter /quit /silent 2>&1 | Out-Null
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'this script must run from an elevated PowerShell'
    exit 1
}
if (-not (Test-Path $Key)) { Write-Host "keyfile not found: $Key"; exit 1 }

Say "=== vc-rs keyfile cross-check ($(Get-Date -Format s)) ==="
Say "keyfile: $Key ($((Get-Item $Key).Length) bytes)"
Dismount-Everything

# 1. vc-rs opens a VeraCrypt-made keyfile container, and that same container
#    mounts in VeraCrypt.  (The mount locks the container file, so the vcrs side
#    is checked first.)
Say '1. VeraCrypt-made keyfile container (vc-kf.vc, password KfTest!2024)'
$vcrsRead = & (Join-Path $Repo 'target\debug\vcrs.exe') info (Join-Path $Repo 'testdata\vc-kf.vc') -p 'KfTest!2024' -k $Key 2>&1 | Out-String
Check 'vcrs-opens-vc-keyfile' ($vcrsRead -match 'volume data size')
$vcrsNoKey = & (Join-Path $Repo 'target\debug\vcrs.exe') info (Join-Path $Repo 'testdata\vc-kf.vc') -p 'KfTest!2024' 2>&1 | Out-String
Check 'vcrs-rejects-missing-keyfile' ($vcrsNoKey -match 'incorrect password')
& $VeraCrypt /volume (Join-Path $Repo 'testdata\vc-kf.vc') /letter Y /password 'KfTest!2024' /keyfile $Key /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-vc-keyfile' (Wait-Drive 'Y:')
Check 'volume-is-fat' ((Wait-FileSystem 'Y:') -eq 'FAT')
& $VeraCrypt /dismount Y /quit /silent 2>&1 | Out-Null

# 2. A vc-rs-made keyfile container (holding a VeraCrypt-created FAT16 image)
#    mounts in VeraCrypt, which reads the file inside it.
Say '2. vc-rs-made keyfile container (ours-kf.vc, password PwKf!2024)'
& $VeraCrypt /volume (Join-Path $Repo 'testdata\ours-kf.vc') /letter Z /password 'PwKf!2024' /keyfile $Key /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-ours-keyfile' (Wait-Drive 'Z:')
$txt = Get-Content 'Z:\fromvc.txt' -Raw -ErrorAction SilentlyContinue
Check 'veracrypt-reads-ours-file' ($null -ne $txt -and $txt.Trim() -eq 'VC-ORIGINAL-12345')
& $VeraCrypt /dismount Z /quit /silent 2>&1 | Out-Null

# 3. Without the keyfile VeraCrypt cannot mount the vc-rs-made container.
Say '3. negative control'
& $VeraCrypt /volume (Join-Path $Repo 'testdata\ours-kf.vc') /letter X /password 'PwKf!2024' /quit /silent 2>&1 | Out-Null
Check 'veracrypt-refuses-missing-keyfile' (-not (Test-Path 'X:\'))
& $VeraCrypt /dismount X /quit /silent 2>&1 | Out-Null

# 4. A directory of keyfiles behaves like VeraCrypt's `-k <dir>`: vc-rs opens the
#    VeraCrypt-made container and VeraCrypt mounts the vc-rs-made one.
Say '4. directory of keyfiles (vc-kfdir.vc / ours-kfdir.vc, -k testdata\kfdir)'
$kfdir = Join-Path $Repo 'testdata\kfdir'
$dirRead = & (Join-Path $Repo 'target\debug\vcrs.exe') info (Join-Path $Repo 'testdata\vc-kfdir.vc') -p 'KfDir!2024' -k $kfdir 2>&1 | Out-String
Check 'vcrs-opens-vc-dirkeyfile' ($dirRead -match 'volume data size')
& $VeraCrypt /volume (Join-Path $Repo 'testdata\vc-kfdir.vc') /letter W /password 'KfDir!2024' /keyfile $kfdir /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-vc-dirkeyfile' (Wait-Drive 'W:')
& $VeraCrypt /dismount W /quit /silent 2>&1 | Out-Null
& $VeraCrypt /volume (Join-Path $Repo 'testdata\ours-kfdir.vc') /letter V /password 'PwKfDir!2024' /keyfile $kfdir /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-ours-dirkeyfile' (Wait-Drive 'V:')
$txt2 = Get-Content 'V:\fromvc.txt' -Raw -ErrorAction SilentlyContinue
Check 'veracrypt-reads-ours-dirkeyfile' ($null -ne $txt2 -and $txt2.Trim() -eq 'VC-ORIGINAL-12345')
& $VeraCrypt /dismount V /quit /silent 2>&1 | Out-Null
Dismount-Everything

Say ''
if ($script:failures.Count -eq 0) { Say 'FAILURES: none' } else { Say ("FAILURES: " + ($script:failures -join ', ')) }
if ($script:failures.Count -eq 0) { Say 'RESULT  : ALL OK' } else { Say 'RESULT  : FAILED' }
