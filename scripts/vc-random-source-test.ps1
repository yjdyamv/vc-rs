# Cross-check `--random-source` (VeraCrypt's reproducible variant) against the
# real VeraCrypt.
#
#   1. create a container twice from the SAME source file  -> byte-identical
#   2. create one from a DIFFERENT source file             -> different bytes
#   3. VeraCrypt mounts one of them and reads a file the container's data area
#      was filled with (a VeraCrypt-made FAT16 image), so the deterministic path
#      is proven to produce ordinary VeraCrypt volumes
#
# Run elevated (the VeraCrypt driver needs it):
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait `
#     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','scripts\vc-random-source-test.ps1'"

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
$Vcrs = Join-Path $Root 'target\debug\vcrs.exe'
$Vera = 'C:\Program Files\VeraCrypt\VeraCrypt.exe'
$Seed = Join-Path $Root '.logs\vc-rs-seed.bin'
$OtherSeed = Join-Path $Root '.logs\vc-rs-seed-other.bin'
$Fat = Join-Path $Root '.logs\vc-fat.bin'
$First = Join-Path $Root 'testdata\vcrs-rs-1.vc'
$Second = Join-Path $Root 'testdata\vcrs-rs-2.vc'
$Third = Join-Path $Root 'testdata\vcrs-rs-3.vc'
$Log = Join-Path $Root '.logs\vc-random-source-test.log'
$Password = 'PwVcRs'
$Pim = 1
$Letter = 'Z'
$failures = 0

function Say($message) { $message | Tee-Object -FilePath $Log -Append }
function Check($name, $ok) {
    if ($ok) { Say "PASS $name" } else { Say "FAIL $name"; $script:failures++ }
}
function Run($exe, [string[]]$argv) {
    $out = & $exe @argv 2>&1
    foreach ($line in $out) { Say "  $line" }
    return $out
}
function SameFile($a, $b) {
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
    cmd /c "fc /b `"$a`" `"$b`" > nul 2>&1" | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function WaitMount($letter, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${letter}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Stop-VeraCrypt {
    Get-Process VeraCrypt -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Say "=== --random-source cross-check $(Get-Date) ==="
Get-Process vcrs, VeraCrypt -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
foreach ($path in @($First, $Second, $Third)) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
foreach ($path in @($Seed, $OtherSeed)) { Remove-Item $path -Force -ErrorAction SilentlyContinue }

# Two source files: the second one differs by a single byte.
[IO.File]::WriteAllBytes($Seed, [Text.Encoding]::ASCII.GetBytes("vc-rs random source for the cross-check`n"))
[IO.File]::WriteAllBytes($OtherSeed, [Text.Encoding]::ASCII.GetBytes("vc-rs random source for the cross-check!`n"))
Check 'seed-files-written' ((Test-Path $Seed) -and (Test-Path $OtherSeed))
Check 'fat-image-present' (Test-Path $Fat)

function NewContainer($path, $seed) {
    Run $Vcrs @('create', $path, '-s', '12M', '-p', $Password, '--pim', "$Pim", '--quick', '--random-source', $seed)
    # The data area is filled with a VeraCrypt-made FAT16 image, so a VeraCrypt
    # mount has something to read.
    Run $Vcrs @('write', $path, '-p', $Password, '--pim', "$Pim", '-o', '0', '--from', $Fat)
}

NewContainer $First $Seed
Check 'first-container-created' (Test-Path $First)
NewContainer $Second $Seed
Check 'second-container-created' (Test-Path $Second)
NewContainer $Third $OtherSeed
Check 'third-container-created' (Test-Path $Third)

Check 'same-seed-gives-the-same-bytes' (SameFile $First $Second)
Check 'a-different-seed-gives-different-bytes' (-not (SameFile $First $Third))

# VeraCrypt has to mount the deterministic container like any other volume.
$mount = Run $Vera @('/volume', $Second, '/letter', $Letter, '/password', $Password, '/pim', "$Pim", '/quit', '/silent')
Check 'veracrypt-mounted' (WaitMount $Letter 30)
if (Test-Path "${Letter}:\") {
    $content = (Get-Content "${Letter}:\fromvc.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'veracrypt-reads-the-marker' ($content -ne $null -and $content.Trim() -eq 'VC-ORIGINAL-12345')
    Set-Content -Path "${Letter}:\from-windows.txt" -Value 'WROTE-THROUGH-VERACRYPT' -Encoding ASCII
    Check 'windows-wrote' ((Get-Content "${Letter}:\from-windows.txt" -Raw).Trim() -eq 'WROTE-THROUGH-VERACRYPT')
    Run $Vera @('/dismount', '/quit', '/silent')
    Start-Sleep -Seconds 2
    Check 'veracrypt-dismounted' (-not (Test-Path "${Letter}:\"))
    # The write went through the container, so vcrs has to see it too.
    $out = Run $Vcrs @('read', $Second, '-p', $Password, '--pim', "$Pim", '-o', '0', '-l', '512', '--out', (Join-Path $Root '.logs\vcrs-rs-vbr.bin'))
    $vbr = [IO.File]::ReadAllBytes((Join-Path $Root '.logs\vcrs-rs-vbr.bin'))
    $oem = [Text.Encoding]::ASCII.GetString($vbr[3..10])
    Check 'deteministic-container-holds-the-filesystem' ($oem -eq 'MSDOS5.0')
} else {
    Check 'veracrypt-reads-the-marker' $false
}

Stop-VeraCrypt
Say "FAILURES: $failures"
if ($failures -eq 0) { Say 'RESULT: ALL OK' } else { Say 'RESULT: FAILED' }
