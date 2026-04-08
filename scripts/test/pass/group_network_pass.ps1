#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets NH-014 and NH-015 network hardening checks to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      NH-014  Sets NoNameReleaseOnDemand=1 (prevents NetBIOS name release on demand)
      NH-015  Sets PerformRouterDiscovery=0 (disables IRDP router discovery)

    What state it leaves the system in:
      NH-014 and NH-015 will report PASS on the next YMC scan.
      Registry changes take effect immediately with no reboot required.

    How to reverse it:
      Run fail/group_network_fail.ps1, or revert to the Proxmox snapshot.
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

# --- NH-014: NoNameReleaseOnDemand ---
# Prevents the system from releasing its NetBIOS name when it receives a name-release
# request. Value must be 1 (enabled) for PASS.
Write-Log "NH-014: Setting NoNameReleaseOnDemand=1..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name 'NoNameReleaseOnDemand' `
    -Value 1

# --- NH-015: PerformRouterDiscovery ---
# Disables IRDP (ICMP Router Discovery Protocol). Value must be 0 for PASS.
# This key lives under the Tcpip Parameters\Interfaces path for each interface,
# but the global Parameters key is what the YMC check reads.
Write-Log "NH-015: Setting PerformRouterDiscovery=0..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'PerformRouterDiscovery' `
    -Value 0

Write-Log "NH-014 and NH-015 set to PASS state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
