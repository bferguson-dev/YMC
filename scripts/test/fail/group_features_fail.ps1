#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets CM-017/CM-018/CM-019/CM-020/SV-008 checks to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      CM-017  Enables WSL (Microsoft-Windows-Subsystem-Linux) feature
      CM-018  Enables TFTP Client feature
      CM-019  Enables Simple TCP/IP Services feature
      CM-020  Sets HideFileExt=1 in HKLM (file extensions hidden — policy violation)
      SV-008  Sets fAllowToGetHelp=1 to enable Remote Assistance

    What state it leaves the system in:
      All five checks will report FAIL on the next YMC scan.

      WARNING: Feature installs (CM-017/018/019) require a REBOOT to fully apply.
      Run within an isolated snapshot cycle. Take a Proxmox snapshot BEFORE
      running this script.

    How to reverse it:
      Run pass/group_features_pass.ps1, or revert to the Proxmox snapshot.
      Snapshot revert is the preferred path — feature install/remove is slow.
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

function Enable-WindowsFeatureIfAbsent {
    param([string]$FeatureName, [string]$CheckId)
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if (-not $feature) {
        Write-Log "  $CheckId ($FeatureName): feature not available on this OS — cannot enable."
        Write-Log "  $CheckId will report an error rather than FAIL. Skipping."
        return
    }
    if ($feature.State -eq 'Enabled') {
        Write-Log "  $CheckId ($FeatureName): already enabled — no action needed."
    } else {
        Write-Log "  $CheckId ($FeatureName): enabling feature (state was $($feature.State))..."
        Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
        Write-Log "  $CheckId ($FeatureName): enabled. Reboot required to complete installation."
    }
}

# --- CM-017: WSL installed (FAIL: should not be installed) ---
Write-Log "CM-017: Enabling WSL (Microsoft-Windows-Subsystem-Linux) — FAIL state..."
Enable-WindowsFeatureIfAbsent -FeatureName 'Microsoft-Windows-Subsystem-Linux' -CheckId 'CM-017'

# --- CM-018: TFTP Client installed (FAIL: should not be installed) ---
Write-Log "CM-018: Enabling TFTP Client — FAIL state..."
Enable-WindowsFeatureIfAbsent -FeatureName 'TFTP' -CheckId 'CM-018'

# --- CM-019: Simple TCP/IP Services installed (FAIL: should not be installed) ---
Write-Log "CM-019: Enabling Simple TCP/IP Services — FAIL state..."
Enable-WindowsFeatureIfAbsent -FeatureName 'SimpleTCP' -CheckId 'CM-019'

# --- CM-020: File extensions hidden (FAIL: HideFileExt must be 0) ---
Write-Log "CM-020: Setting HKLM HideFileExt=1 (file extensions hidden — FAIL state)..."
$explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
if (-not (Test-Path $explorerPath)) {
    New-Item -Path $explorerPath -Force | Out-Null
}
Set-ItemProperty -Path $explorerPath -Name 'HideFileExt' -Value 1 -Type DWord
Write-Log "  Set $explorerPath\HideFileExt = 1"

# --- SV-008: Remote Assistance enabled (FAIL: fAllowToGetHelp must be 0) ---
Write-Log "SV-008: Enabling Remote Assistance (fAllowToGetHelp=1 — FAIL state)..."
$raPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
if (-not (Test-Path $raPath)) {
    New-Item -Path $raPath -Force | Out-Null
}
Set-ItemProperty -Path $raPath -Name 'fAllowToGetHelp' -Value 1 -Type DWord
Write-Log "  Set $raPath\fAllowToGetHelp = 1"

Write-Log ""
Write-Log "CM-017/018/019/020 and SV-008 set to FAIL state."
Write-Log "NOTE: CM-017/018/019 feature changes require a reboot to fully apply."
Write-Log "      CM-020 and SV-008 registry changes take effect immediately."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_features_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
