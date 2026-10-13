# Second cross-check (elevated): can real VeraCrypt read ciphertext that vc-rs wrote?
# The first script proved this for AES/SHA-512/PIM 0. This one covers the paths whose
# parameters are easiest to get subtly wrong:
#   D. cascade encryption algorithm (AES-Twofish-Serpent, i.e. 3 XTS layers)
#   E. Argon2id key derivation (memcost/t_cost/parallelism, 192-byte output)
#   F. non-default PIM (iterations = 15000 + pim*1000)
# Each volume contains a FAT16 image copied from a VeraCrypt-created volume, so a
# successful mount must show the file `fromvc.txt` with the marker text.

$ErrorActionPreference = 'Continue'
$repo  = 'C:\Users\yuan\Desktop\vc-rs'
$vc    = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$td    = Join-Path $repo 'testdata'
$log   = Join-Path $repo '.logs\vc-crosscheck2.log'
Set-Content -Path $log -Value "=== vc-rs -> VeraCrypt ciphertext check $(Get-Date -Format s) ===" -Encoding UTF8

function Say($m) { $m | Tee-Object -FilePath $log -Append | Out-Null; Write-Host $m }
function Run($exe, [string[]]$argv) {
    Say "> $exe $($argv -join ' ')"
    & $exe @argv 2>&1 | ForEach-Object { Say "  $_" }
    Say "  exit=$LASTEXITCODE"
}
function MountVc($file, $letter, $pw, $pim) {
    $a = @('/volume', $file, '/letter', $letter, '/password', $pw, '/quit', '/silent')
    if ($null -ne $pim) { $a += @('/pim', "$pim") }
    Run $vc $a
    Start-Sleep -Seconds 4
    Say "  mounted ${letter}: $([bool](Test-Path "${letter}:\"))"
}
function DismountVc($letter) { Run $vc @('/dismount', $letter, '/quit', '/silent'); Start-Sleep -Seconds 2 }

function Show($letter) {
    if (-not (Test-Path "${letter}:\")) { Say "  !! $letter is NOT mounted"; return }
    Say "  --- dir ${letter}:\ ---"
    Get-ChildItem "${letter}:\" -Force | ForEach-Object { Say ("  {0}  {1}" -f $_.Name, $_.Length) }
    $f = "${letter}:\fromvc.txt"
    if (Test-Path $f) {
        $content = (Get-Content $f -Raw).Trim()
        Say "  fromvc.txt content: '$content'"
        Say "  MARKER OK: $($content -eq 'VC-ORIGINAL-12345')"
    } else {
        Say "  !! fromvc.txt MISSING"
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Say "elevated     : $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
Say "veracrypt    : $((Get-Item $vc).VersionInfo.FileVersion)"

Say ""
Say "D. VeraCrypt mounts a vc-rs volume encrypted with a cascade (AES-Twofish-Serpent, SHA-512)"
MountVc (Join-Path $td 'ours-cascade2.vc') 'W' 'PwCascade2' $null
Show 'W'
DismountVc 'W'

Say ""
Say "E. VeraCrypt mounts a vc-rs volume whose header key was derived with Argon2id (Twofish, PIM 0)"
MountVc (Join-Path $td 'ours-argon2.vc') 'X' 'PwArgon2' $null
Show 'X'
DismountVc 'X'

Say ""
Say "F. VeraCrypt mounts a vc-rs volume created with PIM 12 (AES, SHA-512)"
MountVc (Join-Path $td 'ours-pim.vc') 'Y' 'PwPim' 12
Show 'Y'
DismountVc 'Y'

Say ""
Say "done: $(Get-Date -Format s)"
