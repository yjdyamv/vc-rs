$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-login7.log'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
Say "=== login7 $(Get-Date -Format o) ==="
Say 'RemoveTargetPortal (cleanup):'
& iscsicli RemoveTargetPortal 127.0.0.1 3260 2>&1 | ForEach-Object { Say "  $_" }
Say 'RemoveTarget (cleanup):'
& iscsicli RemoveTarget $Iqn 2>&1 | ForEach-Object { Say "  $_" }
Say 'AddTargetPortal (discovery):'
& iscsicli AddTargetPortal 127.0.0.1 3260 2>&1 | ForEach-Object { Say "  $_" }
Say 'ListTargets:'
& iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
Say 'QLoginTarget:'
& iscsicli QLoginTarget $Iqn 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 12
Say 'SessionList:'
& iscsicli SessionList 1 2>&1 | ForEach-Object { Say "  $_" }
Say 'Disks:'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say 'Volumes:'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
