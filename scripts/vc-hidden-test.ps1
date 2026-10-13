# Hidden volume end-to-end test (must run elevated: Dokany mounting and VeraCrypt both need admin).
#
# testdata/ours-hidden2.vc is prepared beforehand (non-elevated) as:
#   outer volume (20 MiB, AES/SHA-512, password PwOuter) with a FAT16 filesystem
#     copied from a VeraCrypt-created volume (contains fromvc.txt = 'VC-ORIGINAL-12345')
#   hidden volume (8 MiB, password PwHidden) inside it
# The outer filesystem occupies the first 10 MiB of the data area and the hidden
# volume lives in the tail, so both can coexist in one container.
#
# What this proves:
#   1. Windows (through VeraCrypt) can still read the OUTER filesystem even though a
#      hidden volume was carved into the same container.
#   2. VeraCrypt can mount the HIDDEN volume that vc-rs created -- i.e. our hidden
#      header (V2Hidden layout, offset 65536) is byte-compatible.
#   3. A file written through the VeraCrypt mount of the hidden volume is visible to
#      vc-rs's Dokany mount of the same hidden volume, and vice versa.

$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\yuan\Desktop\vc-rs'
$vcrs = Join-Path $repo 'target\debug\vcrs.exe'
$vc   = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$td   = Join-Path $repo 'testdata'
$logs = Join-Path $repo '.logs'
$log  = Join-Path $logs 'vc-hidden-test.log'
$vol  = Join-Path $td 'ours-hidden2.vc'
$pwOuter = 'PwOuter'
$pwHidden = 'PwHidden'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
Set-Content -Path $log -Value "=== vc-rs hidden volume test $(Get-Date -Format s) ===" -Encoding UTF8

function Say($m) { $m | Tee-Object -FilePath $log -Append | Out-Null; Write-Host $m }
function Run($exe, [string[]]$argv) {
    Say "> $exe $($argv -join ' ')"
    & $exe @argv 2>&1 | ForEach-Object { Say "  $_" }
    Say "  exit=$LASTEXITCODE"
}
function ListDrive($letter) {
    if (-not (Test-Path "${letter}:\")) { Say "  !! ${letter}: not available"; return }
    Say "  --- dir ${letter}:\ ---"
    Get-ChildItem "${letter}:\" -Force | ForEach-Object { Say ("  {0}  {1}" -f $_.Name, $_.Length) }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Say "elevated  : $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "veracrypt : $((Get-Item $vc).VersionInfo.FileVersion)"
if (-not (Test-Path $vol)) { Say "!! $vol is missing -- create it first"; exit 1 }

Say ""
Say "0. vc-rs puts a FAT filesystem inside the HIDDEN volume"
Run $vcrs @('format', $vol, '--hidden', '--password', $pwHidden, '--label', 'HIDDENFS')

Say ""
Say "1. VeraCrypt mounts the OUTER volume (must still see the original filesystem)"
Run $vc @('/volume', $vol, '/letter', 'H', '/password', $pwOuter, '/quit', '/silent')
Start-Sleep -Seconds 4
ListDrive 'H'
if (Test-Path 'H:\fromvc.txt') {
    $content = (Get-Content 'H:\fromvc.txt' -Raw)
    Say "  outer file content: '$content'"
    Say "  OUTER OK: $($content.Trim() -eq 'VC-ORIGINAL-12345')"
} else {
    Say "  !! outer filesystem not readable"
}
Run $vc @('/dismount', 'H', '/quit', '/silent')

Say ""
Say "2. VeraCrypt mounts the HIDDEN volume (password only -- no switch selects it)"
Run $vc @('/volume', $vol, '/letter', 'I', '/password', $pwHidden, '/quit', '/silent')
Start-Sleep -Seconds 4
$mountedHidden = Test-Path 'I:\'
Say "  hidden volume mounted: $mountedHidden"
if ($mountedHidden) {
    $v = Get-Volume -DriveLetter I -ErrorAction SilentlyContinue
    if ($v) { Say "  filesystem: $($v.FileSystem)  label: '$($v.FileSystemLabel)'  size: $($v.Size)" }
    ListDrive 'I'
    Set-Content -Path 'I:\hidden.txt' -Value 'WROTE-INTO-HIDDEN' -Encoding Ascii -NoNewline
    Say "  wrote I:\hidden.txt ($((Get-Item 'I:\hidden.txt').Length) bytes) -> '$((Get-Content 'I:\hidden.txt' -Raw))'"
    ListDrive 'I'
} else {
    Say "  !! HIDDEN OK: False (VeraCrypt could not mount the hidden volume)"
}
Run $vc @('/dismount', 'I', '/quit', '/silent')

Say ""
Say "3. vc-rs mounts the HIDDEN volume through Dokany and reads what VeraCrypt wrote"
$out = Join-Path $logs 'vcrs-mount-hidden.out'
$err = Join-Path $logs 'vcrs-mount-hidden.err'
$mp = Start-Process -FilePath $vcrs `
    -ArgumentList @('mount', $vol, '--hidden', '--password', $pwHidden, '--mount-point', 'Z:') `
    -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds 6
Say "  mount process running: $(-not $mp.HasExited)  (pid $($mp.Id))"
if ((Test-Path $err) -and (Get-Item $err).Length -gt 0) { Say "  mount stderr: $((Get-Content $err -Raw))" }
ListDrive 'Z'
if (Test-Path 'Z:\hidden.txt') {
    $content = (Get-Content 'Z:\hidden.txt' -Raw)
    Say "  Z:\hidden.txt: '$content'"
    Say "  HIDDEN ROUND TRIP OK: $($content -eq 'WROTE-INTO-HIDDEN')"
    Set-Content -Path 'Z:\from-vcrs.txt' -Value 'WROTE-BY-VCRS-DOKANY' -Encoding Ascii -NoNewline
    Say "  wrote Z:\from-vcrs.txt through Dokany"
} else {
    Say "  !! hidden.txt written by VeraCrypt is not visible through the Dokany mount"
}
Run $vcrs @('dismount', 'Z:')
Start-Sleep -Seconds 3
if (-not $mp.HasExited) { $mp.WaitForExit(20000) | Out-Null }
Say "  mount process exited: $($mp.HasExited) exit=$($mp.ExitCode)"

Say ""
Say "4. VeraCrypt mounts the HIDDEN volume again: the Dokany write must be there"
Run $vc @('/volume', $vol, '/letter', 'I', '/password', $pwHidden, '/quit', '/silent')
Start-Sleep -Seconds 4
ListDrive 'I'
if (Test-Path 'I:\from-vcrs.txt') {
    $content = (Get-Content 'I:\from-vcrs.txt' -Raw)
    Say "  I:\from-vcrs.txt: '$content'"
    Say "  FULL HIDDEN CHAIN OK: $($content -eq 'WROTE-BY-VCRS-DOKANY')"
} else {
    Say "  !! the file written through Dokany is not visible to VeraCrypt"
}
Run $vc @('/dismount', 'I', '/quit', '/silent')

Say ""
Say "done: $(Get-Date -Format s)"
