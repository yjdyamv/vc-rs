# cleanup stale sessions/targets, then a fresh static login (ReportToPNP=1)
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Log  = Join-Path $Repo '.logs\tmp-login11.log'
$Iqn  = 'iqn.2025-12.io.vcrs:probe'
$init = 'Root\ISCSIPRT\0000_0'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
function Run($cmd) { Say "  > $cmd"; $o = cmd /c "$cmd 2>&1"; foreach ($l in $o) { Say "    $l" } }
Say "=== login11 $(Get-Date -Format o) ==="
Say '--- cleanup'
Run "iscsicli RemoveTarget $Iqn"
Run "iscsicli RemoveTarget iqn.2025-12.io.vcrs:ours-iscsi"
Run 'iscsicli SessionList 1'
Say '--- AddTarget'
Run "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0"
Say "initiator instance: $init"
Say '--- LoginTarget'
Run "iscsicli LoginTarget $Iqn 1 127.0.0.1 3260 `"$init`" 0 0 0 0 0 1 2 0 `"`" `"`" 0 0"
Start-Sleep -Seconds 10
Say '--- sessions after login'
Run 'iscsicli SessionList 1'
Say '--- disks after login'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, IsOffline | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '=== login11 done ==='
