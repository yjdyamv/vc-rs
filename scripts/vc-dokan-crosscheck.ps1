# Dokany <-> VeraCrypt cross-check (must run ELEVATED: VeraCrypt's driver needs admin).
#
# Proves the mount layer end to end in BOTH directions on one container:
#   1. VeraCrypt mounts the container that `vcrs format` created and reads the files
#      that were written through the Dokany drive letter  -> READ-BY-VC.
#   2. VeraCrypt writes a new file into that FAT, then `vcrs mount` reads it back
#      through Dokany                                       -> READ-BY-VCRS.
#
# Usage (from a non-elevated shell, user accepts the UAC prompt):
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\yuan\Desktop\vc-rs\scripts\vc-dokan-crosscheck.ps1'"

$ErrorActionPreference = 'Continue'
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Vol = Join-Path $Repo 'testdata\smoke.vc'
$Pw = 'PwSmoke'
$VcLetter = 'V'
$VcrsLetter = 'S'
$LogDir = Join-Path $Repo '.logs'
$Log = Join-Path $LogDir 'vc-dokan-crosscheck.log'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Say([string]$msg) { $msg | Tee-Object -FilePath $Log -Append | Write-Host }

function Wait-Drive([string]$letter, [int]$seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${letter}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return (Test-Path "${letter}:\")
}

function Stop-Vcrs([string]$letter) {
    # `cmd /c` keeps the child's stderr text out of PowerShell's error stream.
    $out = cmd /c "`"$(Join-Path $Repo 'target\debug\vcrs.exe')" dismount $letter 2>&1"
    foreach ($line in $out) { Say "  $line" }
    Start-Sleep -Seconds 3
}

' ' | Tee-Object -FilePath $Log -Append | Out-Null
Say ("=" * 78)
Say ("vc-dokan-crosscheck {0}" -f (Get-Date -Format 'u'))
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ("elevated            : {0}" -f $elevated)
$Vc = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
Say ("VeraCrypt Version   : {0}" -f (Get-Item $Vc).VersionInfo.ProductVersion)
Say ("container           : {0}" -f $Vol)

# Deterministic starting point: nothing mounted, no leftover files from a previous run.
if (Test-Path "${VcLetter}:\") { & $Vc /dismount $VcLetter /quit /silent | Out-Null; Start-Sleep -Seconds 3 }
if (Test-Path "${VcrsLetter}:\") { Stop-Vcrs $VcrsLetter }

$failures = @()
function Check([string]$name, [bool]$ok) {
    Say ("{0,-14}: {1}" -f $name, $(if ($ok) { 'OK' } else { 'FAIL' }))
    if (-not $ok) { $script:failures += $name }
}

try {
    # ---------------------------------------------------------------- step 1
    Say ''
    Say '--- 1. VeraCrypt reads what was written through the Dokany drive ---'
    & $Vc /volume $Vol /letter $VcLetter /password $Pw /quit /silent | Out-Null
    if (-not (Wait-Drive $VcLetter 25)) { throw "VeraCrypt did not mount $Vol at ${VcLetter}:" }
    Say '  VeraCrypt mounted the vcrs-formatted container'
    Get-ChildItem "${VcLetter}:\" -Recurse -Force |
        Select-Object FullName, Length | Format-Table -AutoSize | Out-String |
        % { $_.TrimEnd() -split "`r?`n" | % { Say "  $_" } }
    $hello = (Get-Content "${VcLetter}:\hello.txt" -Raw -ErrorAction SilentlyContinue)
    $nested = (Get-Content "${VcLetter}:\sub\nested.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'READ-BY-VC' (($null -ne $hello) -and ($hello.Trim() -eq 'hello from dokany') -and
                       ($null -ne $nested) -and ($nested.Trim() -eq 'nested'))

    # ---------------------------------------------------------------- step 2
    Say ''
    Say '--- 2. VeraCrypt writes a file into the vcrs-made FAT, vcrs reads it back ---'
    Set-Content -Path "${VcLetter}:\fromvc.txt" -Value 'VC-WROTE-THIS-42' -NoNewline -Encoding Ascii
    $written = (Get-Content "${VcLetter}:\fromvc.txt" -Raw)
    Check 'VC-WROTE' ($written.Trim() -eq 'VC-WROTE-THIS-42')
    & $Vc /dismount $VcLetter /quit /silent | Out-Null
    Start-Sleep -Seconds 4
    Check 'VC-DISMOUNTED' (-not (Test-Path "${VcLetter}:\"))

    $proc = Start-Process -FilePath (Join-Path $Repo 'target\debug\vcrs.exe') `
        -ArgumentList 'mount', $Vol, '-p', $Pw, '-m', "${VcrsLetter}:" -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $LogDir 'vcrs-mount2.out') `
        -RedirectStandardError (Join-Path $LogDir 'vcrs-mount2.err')
    if (-not (Wait-Drive $VcrsLetter 25)) { throw "vcrs mount did not bring up ${VcrsLetter}:" }
    Say '  vcrs mounted the container through Dokany'
    Get-ChildItem "${VcrsLetter}:\" -Recurse -Force |
        Select-Object FullName, Length | Format-Table -AutoSize | Out-String |
        % { $_.TrimEnd() -split "`r?`n" | % { Say "  $_" } }
    $back = (Get-Content "${VcrsLetter}:\fromvc.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'READ-BY-VCRS' (($null -ne $back) -and ($back.Trim() -eq 'VC-WROTE-THIS-42'))
    $still = (Get-Content "${VcrsLetter}:\hello.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'STILL-THERE' (($null -ne $still) -and ($still.Trim() -eq 'hello from dokany'))
    Stop-Vcrs $VcrsLetter
    if (-not $proc.HasExited) { Say '  note: mount process still running' }
} catch {
    Say ("ERROR: {0}" -f $_)
    $failures += 'exception'
} finally {
    if (Test-Path "${VcLetter}:\") { & $Vc /dismount $VcLetter /quit /silent | Out-Null; Start-Sleep -Seconds 3 }
    if (Test-Path "${VcrsLetter}:\") { Stop-Vcrs $VcrsLetter }
}

Say ''
Say ("FAILURES: {0}" -f $(if ($failures.Count -eq 0) { 'none' } else { ($failures -join ', ') }))
Say ("RESULT  : {0}" -f $(if ($failures.Count -eq 0) { 'ALL OK' } else { 'FAILED' }))
Say ("log     : {0}" -f $Log)
