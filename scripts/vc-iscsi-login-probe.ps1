# Diagnostic: attach the running vc-rs iSCSI target with the Microsoft
# initiator and report every step. Run ELEVATED. Logs to
# .logs/vc-iscsi-login.log (UTF-16LE).

$ErrorActionPreference = 'Continue'
$Iqn = 'iqn.2025-12.io.vcrs:ours-iscsi'
$Log = 'C:\Users\yuan\Desktop\vc-rs\.logs\vc-iscsi-login.log'
Remove-Item -Force $Log -ErrorAction SilentlyContinue

function Say($message) {
    Write-Host $message
    $message | Tee-Object -FilePath $Log -Append | Out-Null
}

Say '=== iSCSI login probe ==='
$svc = Get-Service msiscsi -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') { Start-Service msiscsi; Start-Sleep -Seconds 3 }
Say ('msiscsi: ' + (Get-Service msiscsi).Status)

Say '--- AddTargetPortal 127.0.0.1'
& iscsicli QAddTargetPortal 127.0.0.1 2>&1 | ForEach-Object { Say "  $_" }
Say '--- ListTargets'
& iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
Say '--- AddTarget (static, no discovery)'
& iscsicli AddTarget $Iqn vcrs 127.0.0.1 2>&1 | ForEach-Object { Say "  $_" }
Say '--- ListTargets again'
& iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
Say '--- LoginTarget'
& iscsicli QLoginTarget $Iqn 2>&1 | ForEach-Object { Say "  $_" }
Start-Sleep -Seconds 3
Say '--- SessionList'
& iscsicli SessionList 2>&1 | ForEach-Object { Say "  $_" }
Say '--- ListTargets'
& iscsicli ListTargets 2>&1 | ForEach-Object { Say "  $_" }
Say '--- Get-Disk'
Update-HostStorageCache
Get-Disk | ForEach-Object { Say ("  disk " + $_.Number + ': ' + $_.FriendlyName + ' | ' + $_.PartitionStyle + ' | ' + $_.Size) }
Say '--- from the target log, look for "Unsupported opcode" / login debug output'
