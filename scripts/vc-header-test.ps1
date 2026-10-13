# Cross-check the header backup / restore commands against the real VeraCrypt.
#
# Everything the new batch-1 code touches is verified through VeraCrypt itself:
#   1. create + format a container, put a VeraCrypt-made FAT16 image in it
#   2. vcrs backup-headers                       -> .hc file
#   3. wipe both header groups                    -> container is unopenable
#   4. vcrs restore-headers --from <file>         -> restored, verified
#   5. VeraCrypt mounts it and reads the marker file
#   6. wipe only the primary group, vcrs restore-headers --embedded 
#   7. VeraCrypt mounts it again
#   8. vcrs change (new password + new hash) then VeraCrypt mounts the data
#      area with the new credentials
#
# Run elevated (the VeraCrypt driver needs it):
#   powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait `
#     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','scripts\vc-header-test.ps1'"

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
$Vcrs = Join-Path $Root 'target\debug\vcrs.exe'
$Vol = Join-Path $Root 'testdata\vchdr.vc'
$Hc = Join-Path $Root '.logs\vchdr.hc'
$Fat = Join-Path $Root '.logs\vc-fat.bin'
$Log = Join-Path $Root '.logs\vc-header-test.log'
$Password = 'PwVcHdr'
$NewPassword = 'PwVcHdr2'
$Pim = 1
$Letter = 'Z'
$failures = 0

function Say($message) { $message | Tee-Object -FilePath $Log -Append }
function Check($name, $ok) {
    if ($ok) { Say "PASS $name" } else { Say "FAIL $name"; $script:failures++ }
}
function Stop-Vcrs {
    Get-Process vcrs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
function WaitMount($letter, $seconds) {
    for ($i = 0; $i -lt $seconds; $i++) {
        if (Test-Path "${letter}:\") { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Dismount-Volume($letter) {
    & 'C:\Program Files\VeraCrypt\VeraCrypt.exe' /dismount $letter /quit /silent | Out-Null
    Start-Sleep -Seconds 2
}

Set-Content -Path $Log -Value "VeraCrypt header backup/restore cross-check $(Get-Date -Format s)"
Say "elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

Stop-Vcrs
Remove-Item $Vol -Force -ErrorAction SilentlyContinue
Remove-Item $Hc -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- 1. container
Say ''
Say '--- 1. container with a VeraCrypt-made filesystem in it'
& $Vcrs create $Vol --size 10M --password $Password --pim $Pim | Out-Null
& $Vcrs format $Vol --password $Password --pim $Pim --label VCHDR | Out-Null
& $Vcrs write $Vol --password $Password --pim $Pim --from $Fat --offset 0 | Out-Null
$fatVbr = Join-Path $Root '.logs\vbr-check.bin'
& $Vcrs read $Vol --password $Password --pim $Pim --offset 0 --length 512 --out $fatVbr | Out-Null
$magic = if (Test-Path $fatVbr) { [System.Text.Encoding]::ASCII.GetString([byte[]](Get-Content $fatVbr -Encoding Byte -TotalCount 512)) } else { '' }
Check 'container-holds-the-fat-image' ($magic.Contains('MSDOS5.0'))

# ------------------------------------------------------------- 2. backup file
Say ''
Say '--- 2. vcrs backup-headers'
$out = & $Vcrs backup-headers $Vol --out $Hc 2>&1
Say ($out -join ' ')
Check 'backup-file-written' ((Test-Path $Hc) -and ((Get-Item $Hc).Length -eq 131072))

# ------------------------------------------------------------------- 3. wipe
Say ''
Say '--- 3. wipe both header groups'
$size = (Get-Item $Vol).Length
$zeroes = New-Object byte[] 131072
$stream = [System.IO.File]::OpenWrite($Vol)
$stream.Seek(0, 'Begin') | Out-Null
$stream.Write($zeroes, 0, $zeroes.Length)
$stream.Seek($size - 131072, 'Begin') | Out-Null
$stream.Write($zeroes, 0, $zeroes.Length)
$stream.Close()
$info = & $Vcrs info $Vol --password $Password --pim $Pim 2>&1
Check 'container-refuses-to-open-after-the-wipe' ($LASTEXITCODE -ne 0)

# ------------------------------------------------------- 4./5. restore + mount
Say ''
Say '--- 4. vcrs restore-headers --from'
$out = & $Vcrs restore-headers $Vol --from $Hc --password $Password --pim $Pim 2>&1
Say ($out -join ' ')
Check 'restore-succeeded' ($LASTEXITCODE -eq 0)

Say ''
Say '--- 5. VeraCrypt mounts the restored container'
& 'C:\Program Files\VeraCrypt\VeraCrypt.exe' /volume $Vol /letter $Letter /password $Password /pim $Pim /quit /silent
Check 'veracrypt-mounted' (WaitMount $Letter 30)
if (Test-Path "${Letter}:\") {
    $content = (Get-Content "${Letter}:\fromvc.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'veracrypt-reads-the-data-area' ($content -ne $null -and $content.Trim() -eq 'VC-ORIGINAL-12345')
}
Dismount-Volume $Letter
Check 'veracrypt-dismounted' (-not (Test-Path "${Letter}:\"))

# --------------------------------------------- 6./7. embedded copy + mount
Say ''
Say '--- 6. wipe only the primary group and restore from the embedded copy'
$stream = [System.IO.File]::OpenWrite($Vol)
$stream.Seek(0, 'Begin') | Out-Null
$stream.Write($zeroes, 0, $zeroes.Length)
$stream.Close()
$info = & $Vcrs info $Vol --password $Password --pim $Pim 2>&1
Check 'primary-header-gone' ($LASTEXITCODE -ne 0)
$out = & $Vcrs restore-headers $Vol --embedded --password $Password --pim $Pim 2>&1
Say ($out -join ' ')
Check 'embedded-restore-succeeded' ($LASTEXITCODE -eq 0)

Say ''
Say '--- 7. VeraCrypt mounts it again'
& 'C:\Program Files\VeraCrypt\VeraCrypt.exe' /volume $Vol /letter $Letter /password $Password /pim $Pim /quit /silent
Check 'veracrypt-mounted-again' (WaitMount $Letter 30)
if (Test-Path "${Letter}:\") {
    $content = (Get-Content "${Letter}:\fromvc.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'data-still-intact' ($content -ne $null -and $content.Trim() -eq 'VC-ORIGINAL-12345')
}
Dismount-Volume $Letter

# ------------------------------------------------- 8. change credentials
Say ''
Say '--- 8. vcrs change with a new password and a new hash'
$out = & $Vcrs change $Vol --password $Password --pim $Pim --new-password $NewPassword --new-pim $Pim --new-hash SHA-256 2>&1
Say ($out -join ' ')
Check 'change-succeeded' ($LASTEXITCODE -eq 0)
$old = & $Vcrs info $Vol --password $Password --pim $Pim 2>&1
Check 'old-password-refused' ($LASTEXITCODE -ne 0)

& 'C:\Program Files\VeraCrypt\VeraCrypt.exe' /volume $Vol /letter $Letter /password $NewPassword /hash SHA-256 /pim $Pim /quit /silent
Check 'veracrypt-mounted-with-the-new-credentials' (WaitMount $Letter 30)
if (Test-Path "${Letter}:\") {
    $content = (Get-Content "${Letter}:\fromvc.txt" -Raw -ErrorAction SilentlyContinue)
    Check 'veracrypt-reads-after-the-password-change' ($content -ne $null -and $content.Trim() -eq 'VC-ORIGINAL-12345')
}
Dismount-Volume $Letter

Say ''
if ($failures -eq 0) { Say 'FAILURES: none' } else { Say "FAILURES: $failures" }
Say "RESULT: $(if ($failures -eq 0) { 'ALL OK' } else { 'FAILED' })"
