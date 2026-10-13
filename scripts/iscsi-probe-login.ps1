# Elevated iSCSI probe: register a static target pointing at the logging proxy
# (127.0.0.1:3260 -> the vc-rs target on 127.0.0.1:3261), log in, dump the
# session + disks, then log out.  Log: .logs/iscsi-probe-login.log
param(
    [string]$Iqn = 'iqn.2025-12.io.vcrs:probe',
    [int]$Wait = 8
)
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Log = Join-Path $Repo '.logs\iscsi-probe-login.log'

function Say($m) {
    $m | Tee-Object -FilePath $Log -Append | Out-Null
    Write-Host $m
}

Say "=== probe $Iqn at $(if ($true) { Get-Date -Format o }) ==="

Say '--- cleanup leftovers'
foreach ($t in @('iqn.2025-12.io.vcrs:ours-iscsi', 'iqn.2025-12.io.vcrs:probe', 'iqn.2025-12.io.vcrs:smoke')) {
    $null = cmd /c "iscsicli QLogoutTarget $t 2>&1" | ForEach-Object { Say "  logout $t : $_" }
    $null = cmd /c "iscsicli QDeleteTarget $t 2>&1" | ForEach-Object { Say "  delete $t : $_" }
}
$null = cmd /c "iscsicli RemoveTargetPortal 127.0.0.1 3260 2>&1" | ForEach-Object { Say "  rmportal: $_" }

Say '--- targets before'
$null = cmd /c "iscsicli ListTargets 2>&1" | ForEach-Object { Say "  $_" }

Say '--- AddTarget'
$out = cmd /c "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0 2>&1"
foreach ($line in $out) { Say "  $line" }

Say '--- targets after'
$null = cmd /c "iscsicli ListTargets 2>&1" | ForEach-Object { Say "  $_" }

Say '--- QLoginTarget'
$out = cmd /c "iscsicli QLoginTarget $Iqn 2>&1"
foreach ($line in $out) { Say "  $line" }

Start-Sleep -Seconds $Wait

Say '--- sessions'
$s = Get-IscsiSession -ErrorAction SilentlyContinue
if ($null -eq $s) { Say '  (none)' } else { $s | Format-List | Out-String | ForEach-Object { Say $_ } }

Say '--- disks'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, IsOffline, OperationalStatus |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }

Say '--- logout'
$out = cmd /c "iscsicli QLogoutTarget $Iqn 2>&1"
foreach ($line in $out) { Say "  $line" }
$out = cmd /c "iscsicli QDeleteTarget $Iqn 2>&1"
foreach ($line in $out) { Say "  $line" }

Say '=== probe done ==='
