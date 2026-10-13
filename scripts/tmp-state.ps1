$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-state.log'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
Say "=== state $(Get-Date -Format o) ==="
Say '--- targets'
cmd /c 'iscsicli ListTargets 2>&1' | ForEach-Object { Say "  $_" }
Say '--- sessions'
cmd /c 'iscsicli SessionList 1 2>&1' | ForEach-Object { Say "  $_" }
Say '--- service'
Get-Service msiscsi | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- disks'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- volumes'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size | Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
