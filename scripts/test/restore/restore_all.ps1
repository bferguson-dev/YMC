#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Restores the Windows Server test VM to a known-safe baseline state.

.DESCRIPTION
    What this script does:
      Belt-and-suspenders restore: resets every setting that the FAIL-state scripts
      can modify back to its PASS (compliant) value. Run this after any FAIL-state
      test cycle, in addition to reverting the Proxmox snapshot.

      Note on secedit and LSA: secedit changes write to the Local Security Authority
      (LSA) database. On some hypervisors, snapshot revert does not fully undo LSA
      changes. Always run this restore script AND revert the snapshot.

      Resets:
        - User Rights Assignments (all UR-001 through UR-020)
        - Removes ymc-test-fail dummy user
        - LmCompatibilityLevel=5 (AC-023)
        - Kerberos policy (IA-005/006/007)
        - Audit subcategories (AU-017)
        - HVCI registry (EM-013)
        - HideFileExt=0 (CM-020)
        - Remote Assistance disabled (SV-008)
        - NoNameReleaseOnDemand=1 (NH-014)
        - PerformRouterDiscovery=0 (NH-015)

      Does NOT attempt to:
        - Install/remove Windows optional features (CM-017/018/019) — use snapshot
        - Change TPM hardware state (EM-012) — hardware-only

    What state it leaves the system in:
      All registry and policy settings in a compliant (PASS) state.
      ymc-test-fail local user removed.
      Feature state (WSL, TFTP, SimpleTCP) unchanged — revert snapshot for those.

    How to reverse it:
      Run any fail/*.ps1 script for the desired group.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SID_ADMINISTRATORS = '*S-1-5-32-544'
$SID_GUESTS         = '*S-1-5-32-546'
$SID_BACKUP_OPS     = '*S-1-5-32-551'
$SID_RDP_USERS      = '*S-1-5-32-555'
$SID_LOCAL_SVC      = '*S-1-5-19'
$SID_NET_SVC        = '*S-1-5-20'
$SID_SERVICE        = '*S-1-5-6'

$DUMMY_USER = 'ymc-test-fail'

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] $Message"
}

# --- secedit helpers ---
function Invoke-SeceditExport {
    param([string]$OutPath)
    $null = secedit /export /cfg $OutPath /areas USER_RIGHTS 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "secedit /export failed (exit $LASTEXITCODE)"
    }
}

function Set-SeceditPrivilege {
    param(
        [string]$InfPath,
        [string]$Privilege,
        [string]$SidList
    )
    $lines = [System.IO.File]::ReadAllLines($InfPath, [System.Text.Encoding]::Unicode)
    $found = $false
    $newLines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match "^\s*$([regex]::Escape($Privilege))\s*=") {
            $newLines.Add("$Privilege = $SidList")
            $found = $true
        } else {
            $newLines.Add($line)
        }
    }
    if (-not $found) {
        $out = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $newLines) {
            $out.Add($line)
            if ($line -match '^\[Privilege Rights\]') {
                $out.Add("$Privilege = $SidList")
            }
        }
        $newLines = $out
    }
    [System.IO.File]::WriteAllLines($InfPath, $newLines, [System.Text.Encoding]::Unicode)
}

function Invoke-SeceditImport {
    param([string]$InfPath)
    $db = Join-Path $env:TEMP 'ymc_secedit.sdb'
    if (Test-Path $db) { Remove-Item $db -Force }
    $null = secedit /configure /db $db /cfg $InfPath /areas USER_RIGHTS /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "secedit /configure failed (exit $LASTEXITCODE)"
    }
    if (Test-Path $db) { Remove-Item $db -Force }
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
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
    Write-Log "  Set $Path\$Name = $Value"
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
        Write-Log "  WARNING: auditpol failed for '$Subcategory' (exit $LASTEXITCODE)"
    } else {
        Write-Log "  $Subcategory -> Success:$Success Failure:$Failure"
    }
}

Write-Log "=== YMC Restore All — Starting ==="

# --- Remove dummy test user ---
Write-Log "Removing dummy test user: $DUMMY_USER"
if (Get-LocalUser -Name $DUMMY_USER -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $DUMMY_USER
    Write-Log "  Removed: $DUMMY_USER"
} else {
    Write-Log "  $DUMMY_USER not present — skipping."
}

# --- Restore User Rights Assignments ---
Write-Log "Restoring User Rights Assignments (UR-001–UR-020)..."
$tmp = Join-Path $env:TEMP "ymc_restore_$([System.IO.Path]::GetRandomFileName()).inf"
try {
    Invoke-SeceditExport -OutPath $tmp

    $assignments = @{
        'SeTcbPrivilege'                            = ''
        'SeDebugPrivilege'                          = $SID_ADMINISTRATORS
        'SeLockMemoryPrivilege'                     = ''
        'SeCreateTokenPrivilege'                    = ''
        'SeEnableDelegationPrivilege'               = ''
        'SeCreatePermanentSharedObjectsPrivilege'   = ''
        'SeDenyNetworkLogonRight'                   = $SID_GUESTS
        'SeDenyRemoteInteractiveLogonRight'         = $SID_GUESTS
        'SeNetworkLogonRight'                       = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
        'SeRemoteInteractiveLogonRight'             = "$SID_ADMINISTRATORS,$SID_RDP_USERS"
        'SeBackupPrivilege'                         = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
        'SeRestorePrivilege'                        = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
        'SeLoadDriverPrivilege'                     = $SID_ADMINISTRATORS
        'SeTakeOwnershipPrivilege'                  = $SID_ADMINISTRATORS
        'SeManageVolumePrivilege'                   = $SID_ADMINISTRATORS
        'SeSystemEnvironmentPrivilege'              = $SID_ADMINISTRATORS
        'SeAssignPrimaryTokenPrivilege'             = "$SID_LOCAL_SVC,$SID_NET_SVC"
        'SeImpersonatePrivilege'                    = "$SID_ADMINISTRATORS,$SID_LOCAL_SVC,$SID_NET_SVC,$SID_SERVICE"
        'SeSecurityPrivilege'                       = $SID_ADMINISTRATORS
        'SeInteractiveLogonRight'                   = $SID_ADMINISTRATORS
    }

    foreach ($priv in $assignments.Keys) {
        Set-SeceditPrivilege -InfPath $tmp -Privilege $priv -SidList $assignments[$priv]
    }
    Invoke-SeceditImport -InfPath $tmp
    Write-Log "  User Rights Assignments restored."
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
}

# --- Restore Auth settings ---
Write-Log "Restoring authentication settings (AC-023, IA-005/006/007)..."
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'LmCompatibilityLevel' -Value 5
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxTicketAge' -Value 10
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxServiceAge' -Value 600
Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
    -Name 'MaxClockSkew' -Value 5

# --- Restore Audit subcategories ---
Write-Log "Restoring audit subcategories (AU-017)..."
Set-AuditSubcategory -Subcategory 'Logon'                -Success $true  -Failure $true
Set-AuditSubcategory -Subcategory 'Special Logon'        -Success $true  -Failure $false
Set-AuditSubcategory -Subcategory 'Account Lockout'      -Success $true  -Failure $true
Set-AuditSubcategory -Subcategory 'Process Creation'     -Success $true  -Failure $false
Set-AuditSubcategory -Subcategory 'Security State Change'-Success $true  -Failure $true

# --- Restore HVCI registry ---
Write-Log "Restoring HVCI registry (EM-013)..."
$hvciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
Set-RegistryValue -Path $hvciPath -Name 'Enabled' -Value 1

# --- Restore CM-020: file extensions visible ---
Write-Log "Restoring HideFileExt=0 (CM-020)..."
$explorerPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-RegistryValue -Path $explorerPath -Name 'HideFileExt' -Value 0

# --- Restore SV-008: Remote Assistance disabled ---
Write-Log "Restoring Remote Assistance disabled (SV-008)..."
$raPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
Set-RegistryValue -Path $raPath -Name 'fAllowToGetHelp' -Value 0

# --- Restore NH-014/015: network hardening ---
Write-Log "Restoring network hardening (NH-014, NH-015)..."
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
    -Name 'NoNameReleaseOnDemand' -Value 1
Set-RegistryValue `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
    -Name 'PerformRouterDiscovery' -Value 0

Write-Log ""
Write-Log "=== YMC Restore All — Complete ==="
Write-Log "All registry and policy settings restored to PASS state."
Write-Log "NOTE: Windows optional features (CM-017/018/019) are NOT restored here."
Write-Log "      Revert the Proxmox snapshot to restore feature state."
Write-Log "      qm rollback <VMID> <snapshot-name>"

exit 0
