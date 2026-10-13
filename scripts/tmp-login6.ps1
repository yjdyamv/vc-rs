$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-login6.log'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
Say "=== login6 $(Get-Date -Format o) ==="
Say 'Test-NetConnection 127.0.0.1:3260:'
Test-NetConnection -ComputerName 127.0.0.1 -Port 3260 -InformationLevel Quiet | ForEach-Object { Say "  reachable: $_" }
Say 'AddTargetPortal:'
& iscsicli AddTargetPortal 127.0.0.1 3260 2>&1 | ForEach-Object { Say "  $_" }
Say 'ListTargetPortals:'
& iscsicli ListTargetPortals 2>&1 | ForEach-Object { Say "  $_" }
Say 'LoginTarget:'
& iscsicli LoginTarget $Iqn 1 127.0.0.1 3260 'ROOT\ISCSIPRT\0000_0' 0 0 0 0 0 1 2 0 '""' '""' 0 0 0 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 10
Say 'SessionList:'
cmd /c 'iscsicli SessionList 1 2>&1' | ForEach-Object { Say "  $_" }
Say 'Disks:'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
