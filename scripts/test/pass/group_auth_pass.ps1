#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets AC-023 and IA-005/IA-006/IA-007 authentication checks to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      AC-023  Sets LmCompatibilityLevel=5 (NTLMv2 only, refuse LM/NTLMv1)
      IA-005  Sets MaxTicketAge=10 (Kerberos TGT lifetime, hours <= 10)
      IA-006  Sets MaxServiceAge=600 (Kerberos service ticket lifetime, minutes <= 600)
      IA-007  Sets MaxClockSkew=5 (Kerberos clock skew tolerance, minutes <= 5)

    What state it leaves the system in:
      All four auth checks will report PASS on the next YMC scan.

    How to reverse it:
      Run fail/group_auth_fail.ps1, or revert to the Proxmox snapshot.
      To manually revert AC-023: Set LmCompatibilityLevel=3 (typical non-hardened default)
      To manually revert Kerberos: Remove the registry values to restore defaults.
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
        Write-Log "Created registry key: $Path"
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-Log "Set $Path\$Name = $Value"
}

# --- AC-023: NTLM Authentication Level ---
# LmCompatibilityLevel=5 means: Send NTLMv2 response only; refuse LM and NTLM.
# This is the DISA STIG CAT-I required value.
Write-Log "AC-023: Setting LmCompatibilityLevel=5 (NTLMv2 only)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel' `
    -Value 5

# --- IA-005: Kerberos TGT Ticket Lifetime ---
# MaxTicketAge <= 10 hours. Default Windows value is 10h.
Write-Log "IA-005: Setting Kerberos MaxTicketAge=10 hours..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxTicketAge' `
    -Value 10

# --- IA-006: Kerberos Service Ticket Lifetime ---
# MaxServiceAge <= 600 minutes. Default Windows value is 600.
Write-Log "IA-006: Setting Kerberos MaxServiceAge=600 minutes..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxServiceAge' `
    -Value 600

# --- IA-007: Kerberos Clock Skew ---
# MaxClockSkew <= 5 minutes. Default Windows value is 5.
Write-Log "IA-007: Setting Kerberos MaxClockSkew=5 minutes..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxClockSkew' `
    -Value 5

Write-Log "AC-023 and IA-005/006/007 set to PASS state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
