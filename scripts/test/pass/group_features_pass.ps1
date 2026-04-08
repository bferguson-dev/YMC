#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets CM-017/CM-018/CM-019/CM-020/SV-008 checks to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      CM-017  Removes WSL (Microsoft-Windows-Subsystem-Linux) if installed
      CM-018  Removes TFTP Client (TFTP) if installed
      CM-019  Removes Simple TCP/IP Services (SimpleTCP) if installed
      CM-020  Sets HideFileExt=0 in HKLM so file extensions are always visible
      SV-008  Sets fAllowToGetHelp=0 to disable Remote Assistance

    What state it leaves the system in:
      All five checks will report PASS on the next YMC scan.

      WARNING: CM-017 (WSL removal) and CM-018/CM-019 (feature removal) require
      a REBOOT to fully take effect. Schedule reboots within an isolated snapshot
      cycle. The Proxmox snapshot should be taken BEFORE running this script.

    How to reverse it:
      Run fail/group_features_fail.ps1, or revert to the Proxmox snapshot.
      Reverting snapshot is the preferred recovery path for feature changes.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] $Message"
}

function Remove-WindowsFeatureIfPresent {
    param([string]$FeatureName, [string]$CheckId)
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if (-not $feature) {
        Write-Log "  $CheckId ($FeatureName): feature not found on this OS — skipping."
        return
    }
    if ($feature.State -eq 'Disabled') {
        Write-Log "  $CheckId ($FeatureName): already disabled — no action needed."
    } else {
        Write-Log "  $CheckId ($FeatureName): disabling feature (state was $($feature.State))..."
        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
        Write-Log "  $CheckId ($FeatureName): disabled. Reboot required to complete removal."
    }
}

# --- CM-017: WSL not installed ---
Write-Log "CM-017: Disabling WSL (Microsoft-Windows-Subsystem-Linux)..."
Remove-WindowsFeatureIfPresent -FeatureName 'Microsoft-Windows-Subsystem-Linux' -CheckId 'CM-017'

# --- CM-018: TFTP Client not installed ---
Write-Log "CM-018: Disabling TFTP Client..."
Remove-WindowsFeatureIfPresent -FeatureName 'TFTP' -CheckId 'CM-018'

# --- CM-019: Simple TCP/IP Services not installed ---
Write-Log "CM-019: Disabling Simple TCP/IP Services..."
Remove-WindowsFeatureIfPresent -FeatureName 'SimpleTCP' -CheckId 'CM-019'

# --- CM-020: File extensions visible (HideFileExt=0) ---
Write-Log "CM-020: Setting HKLM HideFileExt=0 (file extensions always visible)..."
$explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
if (-not (Test-Path $explorerPath)) {
    New-Item -Path $explorerPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPath -Name 'HideFileExt' -Value 0 -Type DWord
Write-Log "  Set $explorerPath\HideFileExt = 0"

# --- SV-008: Remote Assistance disabled ---
Write-Log "SV-008: Disabling Remote Assistance (fAllowToGetHelp=0)..."
$raPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
if (-not (Test-Path $raPath)) {
    New-Item -Path $raPath -Force | Out-Null
}
Set-ItemProperty -Path $raPath -Name 'fAllowToGetHelp' -Value 0 -Type DWord
Write-Log "  Set $raPath\fAllowToGetHelp = 0"

Write-Log ""
Write-Log "CM-017/018/019/020 and SV-008 set to PASS state."
Write-Log "NOTE: CM-017/018/019 feature changes require a reboot to fully apply."
Write-Log "      CM-020 and SV-008 registry changes take effect immediately."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
