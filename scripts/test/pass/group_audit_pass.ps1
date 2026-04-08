#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets AU-017 audit subcategory checks to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      Configures the five audit subcategories required by AU-017 via auditpol:
        Logon               -> Success and Failure
        Special Logon       -> Success
        Account Lockout     -> Success and Failure
        Process Creation    -> Success
        Security State Change -> Success and Failure

    What state it leaves the system in:
      AU-017 will report PASS on the next YMC scan.
      auditpol changes take effect immediately with no reboot required.

    How to reverse it:
      Run fail/group_audit_fail.ps1, or revert to the Proxmox snapshot.
      To manually revert: auditpol /set /subcategory:"Logon" /success:disable /failure:disable
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

function Set-AuditSubcategory {
    param(
        [string]$Subcategory,
        [bool]$Success,
        [bool]$Failure
    )
    $successFlag = if ($Success) { 'enable' } else { 'disable' }
    $failureFlag = if ($Failure) { 'enable' } else { 'disable' }
    $null = auditpol /set /subcategory:"$Subcategory" /success:$successFlag /failure:$failureFlag 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for subcategory '$Subcategory' (exit $LASTEXITCODE)"
    }
    Write-Log "  $Subcategory -> Success:$Success Failure:$Failure"
}

Write-Log "AU-017: Setting audit subcategories to PASS state..."

# AU-017 required: Logon = Success and Failure
Set-AuditSubcategory -Subcategory 'Logon' -Success $true -Failure $true

# AU-017 required: Special Logon = Success
Set-AuditSubcategory -Subcategory 'Special Logon' -Success $true -Failure $false

# AU-017 required: Account Lockout = Success and Failure
Set-AuditSubcategory -Subcategory 'Account Lockout' -Success $true -Failure $true

# AU-017 required: Process Creation = Success
Set-AuditSubcategory -Subcategory 'Process Creation' -Success $true -Failure $false

# AU-017 required: Security State Change = Success and Failure
Set-AuditSubcategory -Subcategory 'Security State Change' -Success $true -Failure $true

Write-Log "AU-017 audit subcategories set to PASS state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
