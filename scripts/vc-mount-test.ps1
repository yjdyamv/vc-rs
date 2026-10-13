# End-to-end mount test (must run elevated: Dokany mounting and VeraCrypt both need admin).
#
#   1. vc-rs creates a container and puts a FAT filesystem in it.
#   2. vc-rs mounts it at Z: through Dokany; Windows writes Z:\hello.txt through the
#      drive letter (so the write travels: app -> Dokany -> FAT -> XTS -> container file).
#   3. vc-rs dismounts.
#   4. Real VeraCrypt mounts the *same file* and must see the file written in step 2 —
#      which proves the whole chain produced a genuine VeraCrypt volume.

$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\yuan\Desktop\vc-rs'
$vcrs = Join-Path $repo 'target\debug\vcrs.exe'
$vc   = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$td   = Join-Path $repo 'testdata'
$logs = Join-Path $repo '.logs'
$log  = Join-Path $logs 'vc-mount-test.log'
$vol  = Join-Path $td 'ours-dokan.vc'
$pw   = 'PwDokan'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
Set-Content -Path $log -Value "=== vc-rs Dokany mount test $(Get-Date -Format s) ===" -Encoding UTF8

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

Say ""
Say "1. create + format a container"
if (Test-Path $vol) { Remove-Item $vol -Force }
Run $vcrs @('create', $vol, '--size', '10M', '--password', $pw, '--ea', 'AES')
Run $vcrs @('format', $vol, '--password', $pw, '--label', 'VCRSDOKAN')

Say ""
Say "2. mount with vc-rs (Dokany) and write through the drive letter"
$out = Join-Path $logs 'vcrs-mount.out'
$err = Join-Path $logs 'vcrs-mount.err'
$mp = Start-Process -FilePath $vcrs `
    -ArgumentList @('mount', $vol, '--password', $pw, '--mount-point', 'Z:') `
    -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds 6
Say "  mount process running: $(-not $mp.HasExited)  (pid $($mp.Id))"
if (Test-Path (Join-Path $logs 'vcrs-mount.out')) { Say "  mount stdout: $((Get-Content $out -Raw))" }
if ((Test-Path $err) -and (Get-Item $err).Length -gt 0) { Say "  mount stderr: $((Get-Content $err -Raw))" }
ListDrive 'Z'
if (Test-Path 'Z:\') {
    $drive = Get-PSDrive Z -ErrorAction SilentlyContinue
    if ($drive) { Say "  free space reported: $($drive.Free) of $($drive.Used + $drive.Free)" }
    Set-Content -Path 'Z:\hello.txt' -Value 'written-through-dokany' -Encoding Ascii -NoNewline
    Say "  wrote Z:\hello.txt ($((Get-Item 'Z:\hello.txt').Length) bytes)"
    Say "  read back: '$((Get-Content 'Z:\hello.txt' -Raw))'"
    New-Item -ItemType Directory -Force -Path 'Z:\subdir' | Out-Null
    Set-Content -Path 'Z:\subdir\nested.txt' -Value 'nested' -Encoding Ascii -NoNewline
    ListDrive 'Z'
    Say "  --- dir Z:\subdir ---"
    Get-ChildItem 'Z:\subdir' -Force | ForEach-Object { Say ("  {0}  {1}" -f $_.Name, $_.Length) }
} else {
    Say "  !! Dokany mount failed - see $out / $err"
}

Say ""
Say "3. dismount with vc-rs"
Run $vcrs @('dismount', 'Z:')
Start-Sleep -Seconds 3
Say "  Z: still present: $([bool](Test-Path 'Z:\'))"
if (-not $mp.HasExited) { $mp.WaitForExit(20000) | Out-Null }
Say "  mount process exited: $($mp.HasExited) exit=$($mp.ExitCode)"

Say ""
Say "4. VeraCrypt mounts the very same container (a file written through Dokany must be there)"
Run $vc @('/volume', $vol, '/letter', 'Z', '/password', $pw, '/quit', '/silent')
Start-Sleep -Seconds 4
ListDrive 'Z'
if (Test-Path 'Z:\hello.txt') {
    $content = (Get-Content 'Z:\hello.txt' -Raw)
    Say "  VeraCrypt reads Z:\hello.txt: '$content'"
    Say "  CHAIN OK: $($content -eq 'written-through-dokany')"
} else {
    Say "  !! VeraCrypt cannot see hello.txt"
}
Run $vc @('/dismount', 'Z', '/quit', '/silent')

Say ""
Say "done: $(Get-Date -Format s)"
