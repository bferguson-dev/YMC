#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets NH-014 and NH-015 network hardening checks to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      NH-014  Sets NoNameReleaseOnDemand=0 (allows NetBIOS name release — violation)
      NH-015  Sets PerformRouterDiscovery=2 (enables IRDP router discovery — violation)

    What state it leaves the system in:
      NH-014 and NH-015 will report FAIL on the next YMC scan.
      Registry changes take effect immediately with no reboot required.

    How to reverse it:
      Run pass/group_network_pass.ps1, or revert to the Proxmox snapshot.
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

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Log "  Created registry key: $Path"
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-Log "  Set $Path\$Name = $Value"
}

# --- NH-014: NoNameReleaseOnDemand=0 (FAIL: must be 1) ---
Write-Log "NH-014: Setting NoNameReleaseOnDemand=0 (allows name release — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name 'NoNameReleaseOnDemand' `
    -Value 0

# --- NH-015: PerformRouterDiscovery=2 (FAIL: must be 0) ---
# Value 2 = enabled (system controlled). Value 0 = disabled. Value 1 = enabled always.
Write-Log "NH-015: Setting PerformRouterDiscovery=2 (IRDP enabled — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'PerformRouterDiscovery' `
    -Value 2

Write-Log "NH-014 and NH-015 set to FAIL state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_network_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
