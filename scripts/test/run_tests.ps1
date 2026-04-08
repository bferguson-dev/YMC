#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Orchestrates YMC functional test cycles: snapshot → FAIL state → scan → assert →
    PASS state → scan → assert → rollback.

.DESCRIPTION
    Drives end-to-end functional testing of YMC compliance checks against a live
    Windows Server target. For each test group:
      1. Creates a Proxmox snapshot via SSH to the Proxmox host
      2. Runs the FAIL-state script on the Windows target over WinRM
      3. Invokes the YMC scanner from this Linux host
      4. Asserts that expected check IDs report FAIL
      5. Runs the PASS-state script on the Windows target
      6. Invokes the YMC scanner again
      7. Asserts that the same check IDs now report PASS
      8. Rolls back to the pre-test snapshot

    Test groups:
      user_rights   UR-001–UR-020
      auth          AC-023, IA-005, IA-006, IA-007
      audit         AU-017
      hardware      EM-012 (skipped — hardware-dependent), EM-013
      features      CM-017, CM-018, CM-019, CM-020, SV-008
      network       NH-014, NH-015

    Prerequisites:
      - Proxmox SSH access from this host (key-based auth recommended)
      - WinRM HTTP access to the Windows target from this host
      - YMC installed and runnable: python main.py --host ... --profile disa_stig
      - Windows target configured with baseline/00_winrm_baseline.ps1
      - PowerShell available on the Windows target (for Invoke-Command)

.PARAMETER ProxmoxHost
    Hostname or IP address of the Proxmox host.

.PARAMETER ProxmoxUser
    SSH user for Proxmox (default: root).

.PARAMETER VmId
    Proxmox VM ID of the Windows Server test target.

.PARAMETER WindowsHost
    Hostname or IP address of the Windows Server test target.

.PARAMETER ScanUser
    WinRM username for the YMC scanner account on the Windows target.

.PARAMETER ScanPassword
    WinRM password for the scanner account. Required — no default.

.PARAMETER YmcPath
    Path to the YMC scanner directory (default: ../../..).

.PARAMETER Profile
    YMC compliance profile to use for scans (default: disa_stig).

.PARAMETER Groups
    Comma-separated list of test groups to run. Default: all groups.
    Valid values: user_rights, auth, audit, hardware, features, network

.PARAMETER SkipRollback
    If set, skips snapshot rollback after each group. Useful for debugging
    a specific FAIL or PASS state without losing it.

.EXAMPLE
    # Run all groups
    .\run_tests.ps1 -ProxmoxHost 192.168.1.10 -VmId 105 `
        -WindowsHost 192.168.1.20 -ScanUser ymc-scan -ScanPassword (Read-Host -AsSecureString)

.EXAMPLE
    # Run only auth and network groups
    .\run_tests.ps1 -ProxmoxHost pve1 -VmId 105 -WindowsHost win-test `
        -ScanUser ymc-scan -ScanPassword (Read-Host -AsSecureString) `
        -Groups 'auth,network'

.NOTES
    This script runs from the Linux YMC host — NOT on the Windows target.
    WinRM scripts are pushed to the Windows target via Invoke-Command.
    Proxmox snapshot commands run via ssh to the Proxmox host.

    SAFETY: SkipRollback is for debug use only. Always roll back in production
    test runs to prevent state bleed between groups.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProxmoxHost,

    [string]$ProxmoxUser = 'root',

    [Parameter(Mandatory)]
    [int]$VmId,

    [Parameter(Mandatory)]
    [string]$WindowsHost,

    [Parameter(Mandatory)]
    [string]$ScanUser,

    [Parameter(Mandatory)]
    [SecureString]$ScanPassword,

    [string]$YmcPath = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path,

    [string]$Profile = 'disa_stig',

    [string]$Groups = 'user_rights,auth,audit,hardware,features,network',

    [switch]$SkipRollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Logging ---
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'PASS'  { 'Green' }
        'FAIL'  { 'Red' }
        'WARN'  { 'Yellow' }
        default { 'White' }
    }
    Write-Host "[$ts][$Level] $Message" -ForegroundColor $color
}

$scriptDir = $PSScriptRoot

# Decode secure string to plain text for WinRM credential object
$credential = [PSCredential]::new(
    $ScanUser,
    $ScanPassword
)

# --- Test group definitions ---
# Each group maps to: fail script, pass script, and expected check IDs (FAIL then PASS).
$testGroups = [ordered]@{
    user_rights = @{
        FailScript = Join-Path $scriptDir 'fail\group_user_rights_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_user_rights_pass.ps1'
        CheckIds   = @(
            'UR-001','UR-002','UR-003','UR-004','UR-005','UR-006',
            'UR-007','UR-008','UR-009','UR-010','UR-011','UR-012',
            'UR-013','UR-014','UR-015','UR-016','UR-017','UR-018',
            'UR-019','UR-020'
        )
        Notes = 'Requires revert + restore_all.ps1 for reliable secedit cleanup.'
    }
    auth = @{
        FailScript = Join-Path $scriptDir 'fail\group_auth_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_auth_pass.ps1'
        CheckIds   = @('AC-023','IA-005','IA-006','IA-007')
        Notes = ''
    }
    audit = @{
        FailScript = Join-Path $scriptDir 'fail\group_audit_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_audit_pass.ps1'
        CheckIds   = @('AU-017')
        Notes = ''
    }
    hardware = @{
        FailScript = Join-Path $scriptDir 'fail\group_hardware_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_hardware_pass.ps1'
        # EM-012 (TPM) is hardware-dependent; only assert EM-013 (HVCI) here.
        CheckIds   = @('EM-013')
        Notes = 'EM-012 (TPM) requires vTPM removal in Proxmox config — not automated here.'
    }
    features = @{
        FailScript = Join-Path $scriptDir 'fail\group_features_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_features_pass.ps1'
        # Feature installs require a reboot; only CM-020 and SV-008 assert without reboot.
        # CM-017/018/019 are asserted in a separate manual reboot cycle.
        CheckIds   = @('CM-020','SV-008')
        Notes = 'CM-017/018/019 (feature install/remove) require reboot; assert those manually after reboot.'
    }
    network = @{
        FailScript = Join-Path $scriptDir 'fail\group_network_fail.ps1'
        PassScript = Join-Path $scriptDir 'pass\group_network_pass.ps1'
        CheckIds   = @('NH-014','NH-015')
        Notes = ''
    }
}

# --- WinRM session options ---
$sessionOpts = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$winrmParams = @{
    ComputerName   = $WindowsHost
    Credential     = $credential
    UseSSL         = $false
    SessionOption  = $sessionOpts
    Authentication = 'Basic'
    ErrorAction    = 'Stop'
}

# --- Helper: run a PowerShell script on the Windows target ---
function Invoke-RemoteScript {
    param([string]$ScriptPath)
    $scriptContent = Get-Content -Path $ScriptPath -Raw
    Invoke-Command @winrmParams -ScriptBlock {
        param($sc)
        $tmp = [System.IO.Path]::GetTempFileName() + '.ps1'
        Set-Content $tmp -Value $sc -Encoding UTF8
        try {
            & powershell.exe -ExecutionPolicy Bypass -File $tmp
        } finally {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        }
    } -ArgumentList $scriptContent
}

# --- Helper: create Proxmox snapshot ---
function New-ProxmoxSnapshot {
    param([string]$SnapshotName)
    Write-Log "Creating Proxmox snapshot: $SnapshotName"
    $result = ssh "${ProxmoxUser}@${ProxmoxHost}" "qm snapshot $VmId $SnapshotName 2>&1"
    if ($LASTEXITCODE -ne 0) {
        throw "qm snapshot failed: $result"
    }
    Write-Log "Snapshot created: $SnapshotName"
}

# --- Helper: rollback Proxmox snapshot ---
function Invoke-ProxmoxRollback {
    param([string]$SnapshotName)
    Write-Log "Rolling back to Proxmox snapshot: $SnapshotName"
    $result = ssh "${ProxmoxUser}@${ProxmoxHost}" "qm rollback $VmId $SnapshotName 2>&1"
    if ($LASTEXITCODE -ne 0) {
        throw "qm rollback failed: $result"
    }
    Write-Log "Rollback complete: $SnapshotName"
    # Give the VM time to settle after rollback before the next test
    Start-Sleep -Seconds 30
}

# --- Helper: run YMC scan and parse JSON results ---
function Invoke-YmcScan {
    $scanCmd = "python main.py --host $WindowsHost --user $ScanUser --profile $Profile --format json"
    Write-Log "Running YMC scan: $scanCmd"
    $jsonOut = Push-Location $YmcPath -PassThru | ForEach-Object {
        $plainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ScanPassword)
        )
        $env:YMC_PASSWORD = $plainPw
        $out = & python main.py --host $WindowsHost --user $ScanUser --password env:YMC_PASSWORD `
            --profile $Profile --format json 2>&1
        $env:YMC_PASSWORD = $null
        Pop-Location
        $out
    }
    # Parse the JSON output — find the first JSON object in the output
    $jsonStart = $jsonOut | Select-String -Pattern '^\{' | Select-Object -First 1
    if (-not $jsonStart) {
        throw "YMC scan produced no JSON output. Raw output: $jsonOut"
    }
    $jsonText = ($jsonOut -join "`n")
    return $jsonText | ConvertFrom-Json
}

# --- Helper: assert check status in scan results ---
function Assert-CheckStatus {
    param(
        [PSCustomObject]$ScanResult,
        [string[]]$CheckIds,
        [string]$ExpectedStatus,   # 'FAIL' or 'PASS'
        [string]$GroupName
    )
    $allPassed = $true
    foreach ($id in $CheckIds) {
        $check = $ScanResult.results | Where-Object { $_.check_id -eq $id } | Select-Object -First 1
        if (-not $check) {
            Write-Log "  [$id] NOT FOUND in scan results — check may not be in profile." 'WARN'
            continue
        }
        $actual = $check.status
        if ($actual -eq $ExpectedStatus) {
            Write-Log "  [$id] $actual (expected $ExpectedStatus) PASS" 'PASS'
        } else {
            Write-Log "  [$id] $actual (expected $ExpectedStatus) ASSERTION FAILED" 'FAIL'
            $allPassed = $false
        }
    }
    return $allPassed
}

# --- Main test loop ---
$requestedGroups = $Groups -split ',' | ForEach-Object { $_.Trim() }
$results = [System.Collections.Generic.List[hashtable]]::new()

Write-Log "=== YMC Functional Test Run Starting ==="
Write-Log "Target: $WindowsHost | Profile: $Profile | Groups: $($requestedGroups -join ', ')"

foreach ($groupName in $requestedGroups) {
    if (-not $testGroups.Contains($groupName)) {
        Write-Log "Unknown group: '$groupName' — skipping." 'WARN'
        continue
    }
    $group = $testGroups[$groupName]
    $snapshotName = "ymc_pre_${groupName}_test"
    $groupResult = @{ Group = $groupName; FailAssert = $false; PassAssert = $false; Error = $null }

    Write-Log ""
    Write-Log "=== Group: $groupName ==="
    if ($group.Notes) { Write-Log "NOTE: $($group.Notes)" 'WARN' }

    try {
        # Step 1: Create snapshot
        New-ProxmoxSnapshot -SnapshotName $snapshotName

        # Step 2: Apply FAIL state
        Write-Log "Applying FAIL state: $($group.FailScript)"
        Invoke-RemoteScript -ScriptPath $group.FailScript

        # Step 3: Run YMC scan (expecting FAIL)
        Write-Log "Scanning for FAIL state..."
        $failScan = Invoke-YmcScan

        # Step 4: Assert FAIL
        Write-Log "Asserting FAIL results for group '$groupName'..."
        $groupResult.FailAssert = Assert-CheckStatus -ScanResult $failScan `
            -CheckIds $group.CheckIds -ExpectedStatus 'FAIL' -GroupName $groupName

        # Step 5: Apply PASS state
        Write-Log "Applying PASS state: $($group.PassScript)"
        Invoke-RemoteScript -ScriptPath $group.PassScript

        # Step 6: Run YMC scan (expecting PASS)
        Write-Log "Scanning for PASS state..."
        $passScan = Invoke-YmcScan

        # Step 7: Assert PASS
        Write-Log "Asserting PASS results for group '$groupName'..."
        $groupResult.PassAssert = Assert-CheckStatus -ScanResult $passScan `
            -CheckIds $group.CheckIds -ExpectedStatus 'PASS' -GroupName $groupName

    } catch {
        Write-Log "Group '$groupName' error: $_" 'FAIL'
        $groupResult.Error = $_.ToString()
    } finally {
        # Step 8: Rollback snapshot (always, unless -SkipRollback)
        if ($SkipRollback) {
            Write-Log "SkipRollback set — NOT rolling back. Current state preserved for debugging." 'WARN'
        } else {
            try {
                Invoke-ProxmoxRollback -SnapshotName $snapshotName
            } catch {
                Write-Log "ROLLBACK FAILED for group '$groupName': $_" 'FAIL'
                Write-Log "Manual recovery: ssh ${ProxmoxUser}@${ProxmoxHost} 'qm rollback $VmId $snapshotName'" 'WARN'
            }
        }
    }

    $results.Add($groupResult)
}

# --- Summary ---
Write-Log ""
Write-Log "=== YMC Functional Test Summary ==="
$allPassed = $true
foreach ($r in $results) {
    $failStatus = if ($r.FailAssert) { 'PASS' } else { 'FAIL' }
    $passStatus = if ($r.PassAssert) { 'PASS' } else { 'FAIL' }
    $errStatus  = if ($r.Error)      { "ERROR: $($r.Error)" } else { '' }
    Write-Log "  $($r.Group): FAIL-assert=$failStatus | PASS-assert=$passStatus $errStatus"
    if (-not $r.FailAssert -or -not $r.PassAssert -or $r.Error) {
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Log "All test groups PASSED." 'PASS'
    exit 0
} else {
    Write-Log "One or more test groups FAILED. Review output above." 'FAIL'
    exit 1
}
