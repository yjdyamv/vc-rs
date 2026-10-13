# Elevated: detach every vc-rs iSCSI target and remove it from the initiator,
# so no leftover disk / drive letter stays behind.
# Log: .logs/iscsi-cleanup.log
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Log = Join-Path $Repo '.logs\iscsi-cleanup.log'
$Prefix = 'iqn.2025-12.io.vcrs:'

function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }

Say "=== iSCSI cleanup $(Get-Date -Format o) ==="

Say '--- sessions before'
$out = cmd /c 'iscsicli SessionList 1 2>&1'
foreach ($line in $out) { Say "  $line" }

# Log out every session whose target name belongs to us. The session list looks
# like:   Session Id : <id>  ... Target Name : <iqn>
$sid = $null
foreach ($line in $out) {
    if ($line -match '^\s*Session Id\s*:\s*(\S+)') { $sid = $Matches[1] }
    elseif ($line -match '^\s*Target Name\s*:\s*(\S+)' -and $Matches[1].StartsWith($Prefix)) {
        Say "logging out session $sid ($($Matches[1]))"
        $r = cmd /c "iscsicli LogoutTarget $sid 2>&1"
        foreach ($l in $r) { Say "  $l" }
        $sid = $null
    }
}

Say '--- targets before'
$t = cmd /c 'iscsicli ListTargets 2>&1'
foreach ($line in $t) { Say "  $line" }
foreach ($line in $t) {
    if ($line -match "($Prefix\S+)") {
        $iqn = $Matches[1]
        Say "removing target $iqn"
        $r = cmd /c "iscsicli RemoveTarget $iqn 2>&1"
        foreach ($l in $r) { Say "  $l" }
    }
}

Start-Sleep -Seconds 3
Say '--- disks after'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, OperationalStatus |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- volumes after'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- targets after'
$t = cmd /c 'iscsicli ListTargets 2>&1'
foreach ($line in $t) { Say "  $line" }
Say '=== cleanup done ==='
