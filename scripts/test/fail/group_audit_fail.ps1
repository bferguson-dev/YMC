#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets AU-017 audit subcategory checks to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      Disables the required audit subcategories so that AU-017 reports FAIL:
        Logon               -> No Auditing
        Special Logon       -> No Auditing
        Account Lockout     -> No Auditing
        Process Creation    -> No Auditing
        Security State Change -> No Auditing

    What state it leaves the system in:
      AU-017 will report FAIL on the next YMC scan.
      auditpol changes take effect immediately with no reboot required.

    How to reverse it:
      Run pass/group_audit_pass.ps1, or revert to the Proxmox snapshot.
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

function Disable-AuditSubcategory {
    param([string]$Subcategory)
    $null = auditpol /set /subcategory:"$Subcategory" /success:disable /failure:disable 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for subcategory '$Subcategory' (exit $LASTEXITCODE)"
    }
    Write-Log "  $Subcategory -> No Auditing"
}

Write-Log "AU-017: Disabling required audit subcategories (FAIL state)..."

Disable-AuditSubcategory -Subcategory 'Logon'
Disable-AuditSubcategory -Subcategory 'Special Logon'
Disable-AuditSubcategory -Subcategory 'Account Lockout'
Disable-AuditSubcategory -Subcategory 'Process Creation'
Disable-AuditSubcategory -Subcategory 'Security State Change'

Write-Log "AU-017 audit subcategories set to FAIL state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_audit_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
