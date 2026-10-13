# In-place encryption end-to-end test (must run elevated: VeraCrypt needs admin).
#
# testdata/plain-fat.img is prepared beforehand (non-elevated) as a plain, unencrypted
# image: a FAT16 filesystem copied out of a VeraCrypt-created volume (it contains
# fromvc.txt = 'VC-ORIGINAL-12345'), followed by 128 KiB of zeroed bytes that in-place
# encryption turns into the backup header group.
#
# `vcrs encrypt-in-place testdata/plain-fat.img -p PwInPlace --pim 1` has already been
# run, so the image should now be a normal VeraCrypt volume with
# TC_HEADER_FLAG_NONSYS_INPLACE_ENC set. This script proves that real VeraCrypt can
# mount it and read the data that was encrypted in place, and that writes through the
# VeraCrypt mount survive.

$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\yuan\Desktop\vc-rs'
$vcrs = Join-Path $repo 'target\debug\vcrs.exe'
$vc   = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$td   = Join-Path $repo 'testdata'
$logs = Join-Path $repo '.logs'
$log  = Join-Path $logs 'vc-inplace-test.log'
$vol  = Join-Path $td 'plain-fat.img'
$pw   = 'PwInPlace'
$pim  = '1'
$letter = 'Z'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
Set-Content -Path $log -Value "=== vc-rs in-place encryption test $(Get-Date -Format s) ===" -Encoding UTF8

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

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Say "elevated  : $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "veracrypt : $((Get-Item $vc).VersionInfo.FileVersion)"
if (-not (Test-Path $vol)) { Say "!! $vol is missing"; exit 1 }
Run $vc @('/dismount', $letter, '/quit', '/silent') | Out-Null

Say ""
Say "1. vc-rs still opens the container it encrypted in place"
Run $vcrs @('info', $vol, '--password', $pw, '--pim', $pim)

Say ""
Say "2. VeraCrypt mounts the in-place-encrypted container"
Run $vc @('/volume', $vol, '/letter', $letter, '/password', $pw, '/pim', $pim, '/quit', '/silent')
$mounted = WaitDrive $letter 30
Check 'veracrypt-mounted' $mounted
if (-not $mounted) {
    Say "RESULT: FAILURES: $failures"
    exit 1
}

Say ""
Say "3. The filesystem that was encrypted in place is readable"
Get-ChildItem "${letter}:\" -Force | ForEach-Object { Say ("  {0}  {1}" -f $_.Name, $_.Length) }
$txt = Get-Content "${letter}:\fromvc.txt" -Raw
$txt = $txt.Trim()
Say "  fromvc.txt = '$txt'"
Check 'reads-encrypted-in-place-file' ($txt -eq 'VC-ORIGINAL-12345')

Say ""
Say "4. Windows writes through the VeraCrypt mount"
Set-Content -Path "${letter}:\from-vc-inplace.txt" -Value 'WROTE-IN-INPLACE-VOLUME' -NoNewline
$written = Get-Content "${letter}:\from-vc-inplace.txt" -Raw
Check 'windows-wrote' ($written.Trim() -eq 'WROTE-IN-INPLACE-VOLUME')
Run $vc @('/dismount', $letter, '/quit', '/silent')

Say ""
Say "5. vc-rs sees the file VeraCrypt wrote"
Start-Sleep -Seconds 2
Run $vcrs @('info', $vol, '--password', $pw, '--pim', $pim)
Run $vc @('/volume', $vol, '/letter', $letter, '/password', $pw, '/pim', $pim, '/quit', '/silent')
Start-Sleep -Seconds 4
$back = Get-Content "${letter}:\from-vc-inplace.txt" -Raw
Check 'file-survived-remount' ($back.Trim() -eq 'WROTE-IN-INPLACE-VOLUME')
Run $vc @('/dismount', $letter, '/quit', '/silent')

Say ""
if ($failures -eq 0) { Say "RESULT: ALL OK" } else { Say "RESULT: FAILURES: $failures" }
