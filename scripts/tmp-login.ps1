$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\tmp-login.log'
function Say($m) { Write-Host $m; $m | Out-File -FilePath $Log -Append -Encoding utf8 }
Say "elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
& iscsicli QLogoutTarget $Iqn 2>&1 | Out-Null
& iscsicli QDeleteTarget $Iqn 2>&1 | Out-Null
Start-Sleep -Seconds 2
& iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 '""' '""' 0 0 2>&1 | Select-Object -Last 2 | ForEach-Object { Say "  add: $_" }
& iscsicli QLoginTarget $Iqn 2>&1 | Select-Object -Last 3 | ForEach-Object { Say "  login: $_" }
Start-Sleep -Seconds 12
Say "--- ListSessions"
& iscsicli ListSessions 2>&1 | ForEach-Object { Say "  $_" }
Say "--- Get-Disk (iSCSI)"
Get-Disk | Where-Object { $_.BusType -eq 'iSCSI' } | ForEach-Object { Say ("  disk {0} {1} {2} {3}" -f $_.Number, $_.FriendlyName, $_.Size, $_.OperationalStatus) }
Say "--- done"
