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
function Wait-Drive($drive, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "$drive\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Dismount-Everything {
    foreach ($letter in 'Y', 'Z') {
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

# 1. A VeraCrypt-made keyfile container mounts, and vc-rs reads the same volume.
Say '1. VeraCrypt-made keyfile container (vc-kf.vc, password KfTest!2024)'
& $VeraCrypt /volume (Join-Path $Repo 'testdata\vc-kf.vc') /letter Y /password 'KfTest!2024' /keyfile $Key /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-vc-keyfile' (Wait-Drive 'Y:')
Check 'volume-is-fat' ($null -ne (Get-Volume -DriveLetter Y -ErrorAction SilentlyContinue))
$vcrsRead = & (Join-Path $Repo 'target\debug\vcrs.exe') info (Join-Path $Repo 'testdata\vc-kf.vc') -p 'KfTest!2024' -k $Key 2>&1 | Out-String
Check 'vcrs-opens-vc-keyfile' ($vcrsRead -match 'volume data size')
& $VeraCrypt /dismount Y /quit /silent 2>&1 | Out-Null

# 2. A vc-rs-made keyfile container (holding a VeraCrypt-created FAT16 image)
#    mounts in VeraCrypt, which reads the file inside it.
Say '2. vc-rs-made keyfile container (ours-kf.vc, password PwKf!2024)'
& $VeraCrypt /volume (Join-Path $Repo 'testdata\ours-kf.vc') /letter Z /password 'PwKf!2024' /keyfile $Key /quit /silent 2>&1 | Out-Null
Check 'veracrypt-mounts-ours-keyfile' (Wait-Drive 'Z:')
$txt = Get-Content 'Z:\fromvc.txt' -Raw -ErrorAction SilentlyContinue
Check 'veracrypt-reads-ours-file' ($null -ne $txt -and $txt.Trim() -eq 'VC-ORIGINAL-12345')
Check 'veracrypt-wrong-password-refused' (
    $null -eq (& $VeraCrypt /volume (Join-Path $Repo 'testdata\ours-kf.vc') /letter X /password 'not-the-password' /keyfile $Key /quit /silent 2>&1 | Where-Object { Test-Path 'X:\' }))
& $VeraCrypt /dismount Z /quit /silent 2>&1 | Out-Null
Dismount-Everything

Say ''
if ($script:failures.Count -eq 0) { Say 'FAILURES: none' } else { Say ("FAILURES: " + ($script:failures -join ', ')) }
if ($script:failures.Count -eq 0) { Say 'RESULT  : ALL OK' } else { Say 'RESULT  : FAILED' }
