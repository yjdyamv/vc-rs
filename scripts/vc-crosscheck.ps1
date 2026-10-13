# vc-rs <-> VeraCrypt cross-verification (must run elevated: VeraCrypt needs the driver).
#
# Goal: prove byte-level format compatibility in BOTH directions.
#   A. VeraCrypt creates/writes a volume  -> vc-rs decrypts and sees the file contents.
#   B. vc-rs re-encrypts that very filesystem into its own volume -> VeraCrypt mounts it
#      and reads the file back (so VeraCrypt accepts ciphertext produced by vc-rs).
#   C. vc-rs-created volume mounted by VeraCrypt can be formatted/written by Windows.

$ErrorActionPreference = 'Continue'
$repo  = 'C:\Users\yuan\Desktop\vc-rs'
$vc    = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$vcrs  = Join-Path $repo 'target\debug\vcrs.exe'
$logs  = Join-Path $repo '.logs'
$log   = Join-Path $logs 'vc-crosscheck.log'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
Set-Content -Path $log -Value "=== vc-rs <-> VeraCrypt cross-check $(Get-Date -Format s) ===" -Encoding UTF8

function Say($m) { $m | Tee-Object -FilePath $log -Append | Out-Null; Write-Host $m }

function Run($exe, [string[]]$argv) {
    Say "> $exe $($argv -join ' ')"
    & $exe @argv 2>&1 | ForEach-Object { Say "  $_" }
    Say "  exit=$LASTEXITCODE"
}

function MountVc($file, $letter, $pw) {
    Run $vc @('/volume', $file, '/letter', $letter, '/password', $pw, '/quit', '/silent')
    Start-Sleep -Seconds 3
    Say "  mounted $letter : $([bool](Test-Path "${letter}:\"))"
}

function DismountVc($letter) {
    Run $vc @('/dismount', $letter, '/quit', '/silent')
    Start-Sleep -Seconds 2
}

function MarkerPresent($binPath, $marker) {
    if (-not (Test-Path $binPath)) { return $false }
    $bytes = [IO.File]::ReadAllBytes($binPath)
    $text  = [Text.Encoding]::ASCII.GetString($bytes)
    return $text.Contains($marker)
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Say "elevated     : $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "VeraCrypt    : $((Get-Item $vc).VersionInfo.FileVersion)"
Say "vcrs         : $((& $vcrs --version) -join ' ')"
Run 'sc.exe' @('query', 'veracrypt')

$marker = 'VC-ORIGINAL-12345'
$vcVol  = Join-Path $repo 'testdata\vc-made.vc'      # created by VeraCrypt Format 1.26.30 (FAT16, 10 MiB)
$ourVol = Join-Path $repo 'testdata\ours-fat.vc'     # we create + fill it in step B
$dump   = Join-Path $logs   'data-vc.bin'
$ourPw  = 'VcrsTest!2024'
$vcPw   = 'VcTest!2024'

# ---------------------------------------------------------------- A: VC -> vc-rs
Say "`n=== A. mount the VeraCrypt-created volume and write a marker file (T:) ==="
MountVc $vcVol 'T' $vcPw
Run 'cmd.exe' @('/c', 'dir T:\')
Run 'cmd.exe' @('/c', "echo $marker> T:\fromvc.txt")
Run 'cmd.exe' @('/c', 'type T:\fromvc.txt')
Run 'cmd.exe' @('/c', 'dir T:\')
Run 'cmd.exe' @('/c', 'vol T:')
DismountVc 'T'

Say "`n=== A2. vc-rs opens the same volume and decrypts the whole data area ==="
Run $vcrs @('info', $vcVol, '-p', $vcPw)
Run $vcrs @('read', $vcVol, '-p', $vcPw, '-o', '0', '-l', '10223616', '--out', $dump)
$found = MarkerPresent $dump $marker
Say "  marker '$marker' present in vc-rs-decrypted data area : $found"
Say "  decrypted volume label / OEM (should be FAT16/MSDOS5.0):"
if (Test-Path $dump) {
    $head = [IO.File]::ReadAllBytes($dump)[0..95]
    Say "  $([BitConverter]::ToString($head))"
    Say "  ascii: $([Text.Encoding]::ASCII.GetString($head[3..10]))"
}

# ---------------------------------------------------------------- B: vc-rs -> VC
Say "`n=== B. create a vc-rs volume of the same size and encrypt that filesystem into it ==="
if (Test-Path $ourVol) { Remove-Item -Force $ourVol }
Run $vcrs @('create', $ourVol, '--size', '10M', '-p', $ourPw, '--ea', 'AES', '--prf', 'SHA-512')
Run $vcrs @('write', $ourVol, '-p', $ourPw, '-o', '0', '--from', $dump)
Run $vcrs @('read', $ourVol, '-p', $ourPw, '-o', '0', '-l', '512')

Say "`n=== B2. let VeraCrypt mount vc-rs's own volume (U:) ==="
MountVc $ourVol 'U' $ourPw
Run 'cmd.exe' @('/c', 'dir U:\')
Run 'cmd.exe' @('/c', 'type U:\fromvc.txt')
Run 'cmd.exe' @('/c', 'vol U:')
DismountVc 'U'

# ---------------------------------------------------------------- C: Windows writes through vc-rs volume
Say "`n=== C. mount a fresh vc-rs volume, format it with Windows, write a file ==="
Run $vcrs @('create', $ourVol, '--size', '20M', '-p', $ourPw, '--ea', 'AES-Twofish-Serpent', '--prf', 'SHA-512')
MountVc $ourVol 'V' $ourPw
Run 'cmd.exe' @('/c', 'dir V:\')
Run 'cmd.exe' @('/c', 'format V: /FS:FAT /Q /V:VCRSTEST /Y')
Run 'cmd.exe' @('/c', 'echo vcrs-format-test-67890> V:\fmt.txt')
Run 'cmd.exe' @('/c', 'dir V:\')
Run 'cmd.exe' @('/c', 'type V:\fmt.txt')
Run 'cmd.exe' @('/c', 'vol V:')
DismountVc 'V'

Say "`n=== C2. vc-rs reads what Windows wrote through VeraCrypt (AES-Twofish-Serpent) ==="
$dump2 = Join-Path $logs 'data-ours.bin'
Run $vcrs @('read', $ourVol, '-p', $ourPw, '-o', '0', '-l', '1048576', '--out', $dump2)
Say "  marker 'vcrs-format-test-67890' present after vc-rs decryption : $(MarkerPresent $dump2 'vcrs-format-test-67890')"
Say "  label VCRSTEST present                                        : $(MarkerPresent $dump2 'VCRSTEST')"

# leave nothing mounted
Run $vc @('/dismount', '/quit', '/silent')
Say "`n=== done $(Get-Date -Format s) ==="
