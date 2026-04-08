#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets UR-001 through UR-020 User Rights Assignments to non-compliant (FAIL) state.

.DESCRIPTION
    What this script does:
      Introduces a controlled compliance violation for each of the 20 User Rights
      Assignment checks so that a YMC scan reports FAIL for all UR-xxx check IDs.

      Violations introduced:
        UR-001  SeTcbPrivilege          -> ymc-test-fail user added (must be empty)
        UR-002  SeDebugPrivilege        -> ymc-test-fail added (Admins-only expected)
        UR-003  SeLockMemoryPrivilege   -> ymc-test-fail added (must be empty)
        UR-004  SeCreateTokenPrivilege  -> ymc-test-fail added (must be empty)
        UR-005  SeEnableDelegationPrivilege -> ymc-test-fail added (must be empty)
        UR-006  SeCreatePermanentSharedObjectsPrivilege -> ymc-test-fail added (must be empty)
        UR-007  SeDenyNetworkLogonRight -> set EMPTY (Guests must be in deny list)
        UR-008  SeDenyRemoteInteractiveLogonRight -> set EMPTY (Guests required)
        UR-009  SeNetworkLogonRight     -> Everyone (*S-1-1-0) added (forbidden)
        UR-010  SeRemoteInteractiveLogonRight -> ymc-test-fail added (non-Admins/RDP)
        UR-011  SeBackupPrivilege       -> ymc-test-fail added (Admins+BackupOps only)
        UR-012  SeRestorePrivilege      -> ymc-test-fail added (Admins+BackupOps only)
        UR-013  SeLoadDriverPrivilege   -> ymc-test-fail added (Admins only)
        UR-014  SeTakeOwnershipPrivilege -> ymc-test-fail added (Admins only)
        UR-015  SeManageVolumePrivilege -> ymc-test-fail added (Admins only)
        UR-016  SeSystemEnvironmentPrivilege -> ymc-test-fail added (Admins only)
        UR-017  SeAssignPrimaryTokenPrivilege -> ymc-test-fail added (LocalSvc/NetSvc only)
        UR-018  SeImpersonatePrivilege  -> ymc-test-fail added (allowed set exceeded)
        UR-019  SeSecurityPrivilege     -> ymc-test-fail added (Admins only)
        UR-020  SeInteractiveLogonRight -> Guests (*S-1-5-32-546) added (forbidden)

    What state it leaves the system in:
      All 20 UR checks will report FAIL on the next YMC scan.
      A local user 'ymc-test-fail' is created and used as the violation account.
      The scan user (ymc-scan, in Administrators) is never modified.

    How to reverse it:
      Run pass/group_user_rights_pass.ps1 to restore compliant state, AND
      revert to the Proxmox snapshot (belt-and-suspenders — secedit LSA changes
      can survive snapshot revert inconsistently on some hypervisors).

.NOTES
    The ymc-test-fail user is a local account with no network logon capability.
    It is added to dangerous privileges only for the duration of the FAIL test.
    Restoring via the pass script or snapshot removes all violations.

    secedit only modifies /areas USER_RIGHTS — SYSTEM_ACCESS is never touched.
    No changes are made to the ymc-scan account.
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
$SID_EVERYONE       = '*S-1-1-0'

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

function Set-UserRights {
    param([hashtable]$Assignments)
    $tmp = Join-Path $env:TEMP "ymc_ur_fail_$([System.IO.Path]::GetRandomFileName()).inf"
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

# --- Create dummy test user ---
Write-Log "Creating dummy test user: $DUMMY_USER"
if (-not (Get-LocalUser -Name $DUMMY_USER -ErrorAction SilentlyContinue)) {
    # Generate a random password — this user is never logged in; password is irrelevant.
    $randomPw = [guid]::NewGuid().ToString('N') + 'Aa1!'
    $securePw = ConvertTo-SecureString $randomPw -AsPlainText -Force
    New-LocalUser `
        -Name $DUMMY_USER `
        -Password $securePw `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -Description 'YMC FAIL-state test account — safe to delete' | Out-Null
    Write-Log "Created: $DUMMY_USER"
} else {
    Write-Log "Dummy user already exists: $DUMMY_USER"
}

$dummySid = "*$((Get-LocalUser -Name $DUMMY_USER).SID.Value)"
Write-Log "Dummy user SID: $dummySid"

# --- Apply all FAIL-state privilege assignments ---
Write-Log "Applying FAIL-state User Rights Assignments via secedit..."

$assignments = @{
    # UR-001: SeTcbPrivilege — FAIL: must be empty; add dummy user
    'SeTcbPrivilege'                            = $dummySid
    # UR-002: SeDebugPrivilege — FAIL: must be Admins-only; add dummy user
    'SeDebugPrivilege'                          = "$SID_ADMINISTRATORS,$dummySid"
    # UR-003: SeLockMemoryPrivilege — FAIL: must be empty; add dummy user
    'SeLockMemoryPrivilege'                     = $dummySid
    # UR-004: SeCreateTokenPrivilege — FAIL: must be empty; add dummy user
    'SeCreateTokenPrivilege'                    = $dummySid
    # UR-005: SeEnableDelegationPrivilege — FAIL: must be empty; add dummy user
    'SeEnableDelegationPrivilege'               = $dummySid
    # UR-006: SeCreatePermanentSharedObjectsPrivilege — FAIL: must be empty; add dummy user
    'SeCreatePermanentSharedObjectsPrivilege'   = $dummySid
    # UR-007: SeDenyNetworkLogonRight — FAIL: Guests must be in deny list; remove them
    # Note: we never add the scan user to deny lists; setting empty removes Guests
    'SeDenyNetworkLogonRight'                   = ''
    # UR-008: SeDenyRemoteInteractiveLogonRight — FAIL: Guests required; set empty
    'SeDenyRemoteInteractiveLogonRight'         = ''
    # UR-009: SeNetworkLogonRight — FAIL: Everyone (*S-1-1-0) must not be present; add it
    'SeNetworkLogonRight'                       = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS,$SID_EVERYONE"
    # UR-010: SeRemoteInteractiveLogonRight — FAIL: Admins+RDP only; add dummy user
    'SeRemoteInteractiveLogonRight'             = "$SID_ADMINISTRATORS,$SID_RDP_USERS,$dummySid"
    # UR-011: SeBackupPrivilege — FAIL: Admins+BackupOps only; add dummy user
    'SeBackupPrivilege'                         = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS,$dummySid"
    # UR-012: SeRestorePrivilege — FAIL: Admins+BackupOps only; add dummy user
    'SeRestorePrivilege'                        = "$SID_ADMINISTRATORS,$SID_BACKUP_OPS,$dummySid"
    # UR-013: SeLoadDriverPrivilege — FAIL: Admins only; add dummy user
    'SeLoadDriverPrivilege'                     = "$SID_ADMINISTRATORS,$dummySid"
    # UR-014: SeTakeOwnershipPrivilege — FAIL: Admins only; add dummy user
    'SeTakeOwnershipPrivilege'                  = "$SID_ADMINISTRATORS,$dummySid"
    # UR-015: SeManageVolumePrivilege — FAIL: Admins only; add dummy user
    'SeManageVolumePrivilege'                   = "$SID_ADMINISTRATORS,$dummySid"
    # UR-016: SeSystemEnvironmentPrivilege — FAIL: Admins only; add dummy user
    'SeSystemEnvironmentPrivilege'              = "$SID_ADMINISTRATORS,$dummySid"
    # UR-017: SeAssignPrimaryTokenPrivilege — FAIL: LocalSvc+NetSvc only; add dummy user
    'SeAssignPrimaryTokenPrivilege'             = "$SID_LOCAL_SVC,$SID_NET_SVC,$dummySid"
    # UR-018: SeImpersonatePrivilege — FAIL: Admins+svc accounts only; add dummy user
    'SeImpersonatePrivilege'                    = "$SID_ADMINISTRATORS,$SID_LOCAL_SVC,$SID_NET_SVC,$SID_SERVICE,$dummySid"
    # UR-019: SeSecurityPrivilege — FAIL: Admins only; add dummy user
    'SeSecurityPrivilege'                       = "$SID_ADMINISTRATORS,$dummySid"
    # UR-020: SeInteractiveLogonRight — FAIL: Guests must not be present; add Guests
    'SeInteractiveLogonRight'                   = "$SID_ADMINISTRATORS,$SID_GUESTS"
}

Set-UserRights -Assignments $assignments

Write-Log "All UR-001–UR-020 User Rights Assignments set to FAIL state."
Write-Log "Run YMC scan to verify: python main.py --host <TARGET> --profile disa_stig"
Write-Log "IMPORTANT: Run pass/group_user_rights_pass.ps1 AND revert snapshot after verifying FAIL results."

exit 0
