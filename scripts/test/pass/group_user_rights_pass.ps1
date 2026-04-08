#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets UR-001 through UR-020 User Rights Assignments to compliant (PASS) state.

.DESCRIPTION
    What this script does:
      Configures all 20 User Rights Assignment checks to their expected PASS state
      using secedit. Each privilege is set to exactly the SIDs required by the
      YMC compliance checks.

      Privileges set to EMPTY (no accounts):
        UR-001  SeTcbPrivilege
        UR-003  SeLockMemoryPrivilege
        UR-004  SeCreateTokenPrivilege
        UR-005  SeEnableDelegationPrivilege
        UR-006  SeCreatePermanentSharedObjectsPrivilege

      Privileges set to Administrators only:
        UR-002  SeDebugPrivilege
        UR-013  SeLoadDriverPrivilege
        UR-014  SeTakeOwnershipPrivilege
        UR-015  SeManageVolumePrivilege
        UR-016  SeSystemEnvironmentPrivilege
        UR-019  SeSecurityPrivilege

      Privileges set to Administrators + Backup Operators:
        UR-011  SeBackupPrivilege
        UR-012  SeRestorePrivilege

      UR-010  SeRemoteInteractiveLogonRight  -> Administrators, Remote Desktop Users
      UR-017  SeAssignPrimaryTokenPrivilege  -> Local Service, Network Service
      UR-018  SeImpersonatePrivilege         -> Administrators, Local/Network/Service
      UR-007  SeDenyNetworkLogonRight        -> Guests (must INCLUDE Guests)
      UR-008  SeDenyRemoteInteractiveLogonRight -> Guests (must INCLUDE Guests)
      UR-009  SeNetworkLogonRight            -> Administrators, Backup Operators (no Everyone)
      UR-020  SeInteractiveLogonRight        -> Administrators (no Guests)

    What state it leaves the system in:
      All 20 UR checks should report PASS on the next YMC scan.
      The ymc-test-fail dummy user is removed if present.

    How to reverse it:
      Run fail/group_user_rights_fail.ps1 to introduce violations, or
      revert to the Proxmox snapshot taken before this test group.

.NOTES
    Safe to run multiple times (idempotent).
    secedit changes are applied immediately; no reboot required.
    Only /areas USER_RIGHTS is modified — SYSTEM_ACCESS is never touched.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Well-known SIDs used by YMC checks
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
# Export current USER_RIGHTS policy to a temp .inf file.
function Invoke-SeceditExport {
    param([string]$OutPath)
    $null = secedit /export /cfg $OutPath /areas USER_RIGHTS 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "secedit /export failed (exit $LASTEXITCODE)"
    }
}

# Modify a single privilege line in a secedit .inf file.
# secedit exports UTF-16 LE; use .NET File I/O to preserve encoding.
function Set-SeceditPrivilege {
    param(
        [string]$InfPath,
        [string]$Privilege,
        [string]$SidList   # comma-separated "*SID,*SID" or "" for empty
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
        # Insert the new line immediately after the [Privilege Rights] section header.
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

# Apply a secedit .inf to the USER_RIGHTS area.
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

# Apply a complete set of privilege assignments in one secedit round-trip.
# $assignments is a hashtable: @{ 'SeTcbPrivilege' = ''; 'SeDebugPrivilege' = '*S-1-5-32-544' }
function Set-UserRights {
    param([hashtable]$Assignments)
    $tmp = Join-Path $env:TEMP "ymc_ur_pass_$([System.IO.Path]::GetRandomFileName()).inf"
    try {
        Invoke-SeceditExport -OutPath $tmp
        foreach ($priv in $Assignments.Keys) {
            Set-SeceditPrivilege -InfPath $tmp -Privilege $priv -SidList $Assignments[$priv]
        }
        Invoke-SeceditImport -InfPath $tmp
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force }
    }
}

# --- Remove dummy test user if present ---
Write-Log "Checking for dummy test user: $DUMMY_USER"
if (Get-LocalUser -Name $DUMMY_USER -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $DUMMY_USER
    Write-Log "Removed dummy test user: $DUMMY_USER"
} else {
    Write-Log "Dummy test user not present."
}

# --- Apply all PASS-state privilege assignments ---
Write-Log "Applying PASS-state User Rights Assignments via secedit..."

$assignments = @{
    # UR-001: SeTcbPrivilege — must be empty
    'SeTcbPrivilege'                            = ''
    # UR-002: SeDebugPrivilege — Administrators only
    'SeDebugPrivilege'                          = $SID_ADMINISTRATORS
    # UR-003: SeLockMemoryPrivilege — must be empty
    'SeLockMemoryPrivilege'                     = ''
    # UR-004: SeCreateTokenPrivilege — must be empty
    'SeCreateTokenPrivilege'                    = ''
    # UR-005: SeEnableDelegationPrivilege — must be empty
    'SeEnableDelegationPrivilege'               = ''
    # UR-006: SeCreatePermanentSharedObjectsPrivilege — must be empty
    'SeCreatePermanentSharedObjectsPrivilege'   = ''
    # UR-007: SeDenyNetworkLogonRight — must include Guests
    'SeDenyNetworkLogonRight'                   = $SID_GUESTS
    # UR-008: SeDenyRemoteInteractiveLogonRight — must include Guests
    'SeDenyRemoteInteractiveLogonRight'         = $SID_GUESTS
    # UR-009: SeNetworkLogonRight — must NOT include Everyone
    'SeNetworkLogonRight'                       = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
    # UR-010: SeRemoteInteractiveLogonRight — Admins + RDP Users only
    'SeRemoteInteractiveLogonRight'             = "$SID_ADMINISTRATORS,$SID_RDP_USERS"
    # UR-011: SeBackupPrivilege — Admins + Backup Operators
    'SeBackupPrivilege'                         = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
    # UR-012: SeRestorePrivilege — Admins + Backup Operators
    'SeRestorePrivilege'                        = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS"
    # UR-013: SeLoadDriverPrivilege — Administrators only
    'SeLoadDriverPrivilege'                     = $SID_ADMINISTRATORS
    # UR-014: SeTakeOwnershipPrivilege — Administrators only
    'SeTakeOwnershipPrivilege'                  = $SID_ADMINISTRATORS
    # UR-015: SeManageVolumePrivilege — Administrators only
    'SeManageVolumePrivilege'                   = $SID_ADMINISTRATORS
    # UR-016: SeSystemEnvironmentPrivilege — Administrators only
    'SeSystemEnvironmentPrivilege'              = $SID_ADMINISTRATORS
    # UR-017: SeAssignPrimaryTokenPrivilege — Local Service + Network Service only
    'SeAssignPrimaryTokenPrivilege'             = "$SID_LOCAL_SVC,$SID_NET_SVC"
    # UR-018: SeImpersonatePrivilege — Admins + Local/Network/Service
    'SeImpersonatePrivilege'                    = "$SID_ADMINISTRATORS,$SID_LOCAL_SVC,$SID_NET_SVC,$SID_SERVICE"
    # UR-019: SeSecurityPrivilege — Administrators only
    'SeSecurityPrivilege'                       = $SID_ADMINISTRATORS
    # UR-020: SeInteractiveLogonRight — Administrators only (Guests must NOT be present)
    'SeInteractiveLogonRight'                   = $SID_ADMINISTRATORS
}

Set-UserRights -Assignments $assignments

Write-Log "All UR-001–UR-020 User Rights Assignments set to PASS state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"

exit 0
