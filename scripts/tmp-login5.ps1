$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-login5.log'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
Say "=== login5 $(Get-Date -Format o) ==="
Say 'LoginTarget with 18 args (Mapping Count = 0):'
& iscsicli LoginTarget $Iqn 1 127.0.0.1 3260 'ROOT\ISCSIPRT\0000_0' 0 0 0 0 0 1 2 0 '""' '""' 0 0 0 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 10
Say 'SessionList:'
cmd /c 'iscsicli SessionList 1 2>&1' | ForEach-Object { Say "  $_" }
Say 'Disks:'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say 'Volumes:'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
