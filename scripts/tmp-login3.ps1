$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-login3.log'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
Say "=== login3 $(Get-Date -Format o) ==="
Say 'AddTarget:'
cmd /c "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0" 2>&1 | ForEach-Object { Say "  $_" }
Say 'ListTargets:'
cmd /c 'iscsicli ListTargets 2>&1' | ForEach-Object { Say "  $_" }
Say 'LoginTarget:'
cmd /c "iscsicli LoginTarget $Iqn 1 127.0.0.1 3260 `"ROOT\ISCSIPRT\0000_0`" 0 0 0 0 0 1 2 0 `"`" `"`" 0 0" 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 8
Say 'SessionList:'
cmd /c 'iscsicli SessionList 1 2>&1' | ForEach-Object { Say "  $_" }
Say 'Disks:'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, OperationalStatus | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
