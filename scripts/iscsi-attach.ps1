<#
.SYNOPSIS
  Attach a vc-rs iSCSI volume that is already being served by `vcrs mount`.
.DESCRIPTION
  Run `vcrs mount <container> -p <password> --raw` in another (normal) shell first;
  it prints the target name.  This script then registers that target statically and
  logs in with ReportToPNP, so Windows creates a disk device you can partition and
  format with its own drivers.  Run it from an ELEVATED PowerShell.
.EXAMPLE
  .\iscsi-attach.ps1 iqn.2025-12.io.vcrs:manual
#>
param(
    [Parameter(Mandatory = $true)][string]$Iqn,
    [string]$Address = '127.0.0.1',
    [int]$Port = 3260,
    [int]$Wait = 10
)
$Log = Join-Path (Split-Path -Parent $PSScriptRoot) '.logs\iscsi-attach.log'
function Say($m) { $m | Tee-Object -FilePath $Log -Append | Out-Null; Write-Host $m }
function Run($cmd) { Say "  > $cmd"; foreach ($l in (cmd /c "$cmd 2>&1")) { Say "    $l" } }
Say "=== iscsi-attach $(Get-Date -Format o) $Iqn ==="
$elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say "elevated: $elevated"
if (-not $elevated) { Say 'this script must run elevated (the Microsoft iSCSI Initiator needs admin)'; exit 1 }
if (-not (Get-Service msiscsi -ErrorAction SilentlyContinue) -or (Get-Service msiscsi).Status -ne 'Running') {
    Say 'starting the msiscsi service'; Start-Service msiscsi -ErrorAction SilentlyContinue
}
Run "iscsicli QLogoutTarget $Iqn"
Run "iscsicli RemoveTarget $Iqn"
Run "iscsicli AddTarget $Iqn vcrs $Address $Port 0 0 0 0 0 8 0 0 `"`" `"`" 0 0"
Run "iscsicli QLoginTarget $Iqn"
Start-Sleep -Seconds $Wait
Say '--- sessions'
Run 'iscsicli SessionList 1'
Say '--- disks'
Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle, IsOffline |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- partitions'
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '--- volumes'
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, HealthStatus |
    Format-Table -AutoSize | Out-String | ForEach-Object { Say $_ }
Say '=== iscsi-attach done ==='
