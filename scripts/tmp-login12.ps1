# the working recipe: static AddTarget + QLoginTarget
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Log  = Join-Path $Repo '.logs\tmp-login12.log'
$Iqn  = 'iqn.2025-12.io.vcrs:probe'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
function Run($cmd) { Say "  > $cmd"; $o = cmd /c "$cmd 2>&1"; foreach ($l in $o) { Say "    $l" } }
Say "=== login12 $(Get-Date -Format o) ==="
Run "iscsicli RemoveTarget $Iqn"
Run "iscsicli QLogoutTarget $Iqn"
Say '--- AddTarget'
Run "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0"
Say '--- QLoginTarget'
Run "iscsicli QLoginTarget $Iqn"
Start-Sleep -Seconds 10
Say '--- sessions'
Run 'iscsicli SessionList 1'
Say '--- disks'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, IsOffline | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- partitions'
Get-Partition -DiskNumber 1 -ErrorAction SilentlyContinue | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '=== login12 done ==='
