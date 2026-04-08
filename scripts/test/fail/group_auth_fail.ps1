#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets AC-023 and IA-005/IA-006/IA-007 authentication checks to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      AC-023  Sets LmCompatibilityLevel=3 (allows NTLMv1 — policy violation)
      IA-005  Sets MaxTicketAge=20 (> 10 hour limit — policy violation)
      IA-006  Sets MaxServiceAge=1200 (> 600 minute limit — policy violation)
      IA-007  Sets MaxClockSkew=30 (> 5 minute limit — policy violation)

    What state it leaves the system in:
      All four auth checks will report FAIL on the next YMC scan.

    How to reverse it:
      Run pass/group_auth_pass.ps1, or revert to the Proxmox snapshot.
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
# LmCompatibilityLevel=3 allows NTLMv1 — below the required threshold of 5.
# YMC check: PASS requires == 5; WARNING if == 4; FAIL if < 4. Use 3 for clear FAIL.
Write-Log "AC-023: Setting LmCompatibilityLevel=3 (allows NTLMv1 — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel' `
    -Value 3

# --- IA-005: Kerberos TGT Ticket Lifetime ---
# MaxTicketAge=20 exceeds the 10-hour limit.
Write-Log "IA-005: Setting Kerberos MaxTicketAge=20 hours (exceeds limit — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxTicketAge' `
    -Value 20

# --- IA-006: Kerberos Service Ticket Lifetime ---
# MaxServiceAge=1200 exceeds the 600-minute limit.
Write-Log "IA-006: Setting Kerberos MaxServiceAge=1200 minutes (exceeds limit — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxServiceAge' `
    -Value 1200

# --- IA-007: Kerberos Clock Skew ---
# MaxClockSkew=30 exceeds the 5-minute limit.
Write-Log "IA-007: Setting Kerberos MaxClockSkew=30 minutes (exceeds limit — FAIL state)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxClockSkew' `
    -Value 30

Write-Log "AC-023 and IA-005/006/007 set to FAIL state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_auth_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
