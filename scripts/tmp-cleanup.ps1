# remove every target/session this project ever created and confirm no disk is left
$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-cleanup.log'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
function Run($cmd) { Say "  > $cmd"; $o = cmd /c "$cmd 2>&1"; foreach ($l in $o) { Say "    $l" } }
Say "=== cleanup $(Get-Date -Format o) ==="
foreach ($iqn in @('iqn.2025-12.io.vcrs:probe','iqn.2025-12.io.vcrs:ours-iscsi','iqn.2025-12.io.vcrs:volume')) {
    Run "iscsicli QLogoutTarget $iqn"
    Run "iscsicli RemoveTarget $iqn"
}
Run 'iscsicli SessionList 1'
Say '--- disks:'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '=== cleanup done ==='
