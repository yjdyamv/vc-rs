# Elevated iSCSI probe #2: register the static target, log in WITH ReportToPNP=1
# so Windows creates a disk device, then dump disks/partitions/volumes.
# Log: .logs/iscsi-probe-login2.log
param(
    [string]$Iqn = 'iqn.2025-12.io.vcrs:probe',
    [int]$Wait = 10
)
$Repo = 'C:\Users\yuan\Desktop\vc-rs'
$Log = Join-Path $Repo '.logs\iscsi-probe-login2.log'

function Say($m) {
    $m | Tee-Object -FilePath $Log -Append | Out-Null
    Write-Host $m
}
function Run($cmd) {
    $out = cmd /c "$cmd 2>&1"
    foreach ($line in $out) { Say "  $line" }
}

Say "=== probe2 $Iqn at $(Get-Date -Format o) ==="

# ---- initiator instance name -------------------------------------------------
Say '--- ListInitiators'
$init = $null
$out = cmd /c 'iscsicli ListInitiators 2>&1'
foreach ($line in $out) {
    Say "  $line"
    if ($line -match 'Initiator Instance\s*:\s*(\S+)') { $init = $Matches[1] }
}
if (-not $init) { $init = 'Root\ISCSIPRT\0000_0' }
Say "  -> using instance '$init'"

Say '--- AddTarget'
Run "iscsicli AddTarget $Iqn vcrs 127.0.0.1 3260 0 0 0 0 0 8 0 0 `"`" `"`" 0 0"

Say '--- LoginTarget (ReportToPNP = 1)'
Run "iscsicli LoginTarget $Iqn 1 127.0.0.1 3260 `"$init`" 0 0 0 0 0 1 2 0 `"`" `"`" 0 0"

Start-Sleep -Seconds $Wait

Say '--- sessions'
Run 'iscsicli SessionList 1'

Say '--- raw disks'
Get-Disk | Select-Object Number, FriendlyName, SerialNumber, Size, PartitionStyle, IsOffline, IsReadOnly, OperationalStatus |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }

Say '--- partitions'
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type, IsOffline |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }

Say '--- volumes'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, HealthStatus |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }

Say '--- wmi disks'
Get-CimInstance Win32_DiskDrive | Select-Object Index, Model, InterfaceType, Size, Partitions |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }

Say '=== probe2 done ==='
