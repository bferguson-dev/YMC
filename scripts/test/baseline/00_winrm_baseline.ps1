#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configures a Windows Server VM as a baseline YMC functional test target.

.DESCRIPTION
    What this script does:
      - Enables and starts the WinRM service
      - Configures WinRM HTTP listener (port 5985) for isolated test network use
      - Opens Windows Firewall for WinRM HTTP
      - Creates a local administrator account for the YMC scanner to use
      - Verifies connectivity is possible

    What state it leaves the system in:
      - WinRM running, firewall rule active, scan user in Administrators group
      - System is ready to receive YMC compliance scan connections

    How to reverse it:
      - Disable-PSRemoting -Force
      - Remove-LocalUser -Name <ScanUser>
      - Remove-NetFirewallRule -Name 'YMC-WinRM-HTTP'
      - Stop-Service winrm; Set-Service winrm -StartupType Disabled

.PARAMETER ScanUser
    Name of the local account that the YMC scanner will use to connect.
    Default: ymc-scan

.PARAMETER ScanUserPassword
    SecureString password for the scan user account. Required — no default.

.NOTES
    Run this script once before functional testing begins.
    The VM should be on an isolated test network (no production exposure).
    After running, take a Proxmox snapshot: qm snapshot <VMID> baseline_ready
#>
[CmdletBinding()]
param(
    [string]$ScanUser = 'ymc-scan',

    [Parameter(Mandatory)]
    [SecureString]$ScanUserPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Output "[$ts] $Message"
}

Write-Log "=== YMC Baseline Configuration Starting ==="

# --- WinRM ---
Write-Log "Enabling PSRemoting..."
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Write-Log "PSRemoting enabled."

Write-Log "Setting WinRM service to auto-start..."
Set-Service -Name winrm -StartupType Automatic
Start-Service -Name winrm
Write-Log "WinRM service started."

# Ensure HTTP listener exists on all interfaces (test VM only — no TLS needed for isolation)
$existingListener = Get-WSManInstance -ResourceURI winrm/config/listener `
    -SelectorSet @{Address='*'; Transport='HTTP'} -ErrorAction SilentlyContinue
if (-not $existingListener) {
    New-WSManInstance -ResourceURI winrm/config/listener `
        -SelectorSet @{Address='*'; Transport='HTTP'} `
        -ValueSet @{Enabled='True'} | Out-Null
    Write-Log "Created WinRM HTTP listener."
} else {
    Write-Log "WinRM HTTP listener already exists."
}

# --- Firewall ---
Write-Log "Configuring firewall rule for WinRM HTTP (port 5985)..."
$fwRule = Get-NetFirewallRule -Name 'YMC-WinRM-HTTP' -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule `
        -Name 'YMC-WinRM-HTTP' `
        -DisplayName 'YMC WinRM HTTP (test)' `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 5985 `
        -Action Allow `
        -Profile Any | Out-Null
    Write-Log "Firewall rule created: YMC-WinRM-HTTP."
} else {
    Write-Log "Firewall rule already exists: YMC-WinRM-HTTP."
}

# --- Scan user account ---
Write-Log "Configuring scan user account: $ScanUser"
$existingUser = Get-LocalUser -Name $ScanUser -ErrorAction SilentlyContinue
if (-not $existingUser) {
    New-LocalUser `
        -Name $ScanUser `
        -Password $ScanUserPassword `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -Description 'YMC scanner account — functional test only' | Out-Null
    Write-Log "Created local user: $ScanUser"
} else {
    # Update password in case it changed
    Set-LocalUser -Name $ScanUser -Password $ScanUserPassword
    Write-Log "Updated password for existing user: $ScanUser"
}

# Ensure scan user is in Administrators group
$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
$isAdmin = $admins | Where-Object { $_.Name -like "*\$ScanUser" -or $_.Name -eq $ScanUser }
if (-not $isAdmin) {
    Add-LocalGroupMember -Group 'Administrators' -Member $ScanUser
    Write-Log "Added $ScanUser to Administrators group."
} else {
    Write-Log "$ScanUser is already in Administrators group."
}

# --- WinRM auth: allow basic auth over HTTP (test VM only) ---
Write-Log "Enabling Basic auth on WinRM service (test VM only)..."
Set-WSManInstance -ResourceURI winrm/config/service/auth `
    -ValueSet @{Basic='true'} | Out-Null
Set-WSManInstance -ResourceURI winrm/config/service `
    -ValueSet @{AllowUnencrypted='true'} | Out-Null
Write-Log "WinRM Basic auth and unencrypted transport enabled."

# --- Verification ---
Write-Log "Verifying WinRM is listening..."
$listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
foreach ($l in $listeners) {
    Write-Log "  Listener: Transport=$($l.Transport) Port=$($l.Port) Enabled=$($l.Enabled)"
}

Write-Log "=== Baseline configuration complete ==="
Write-Log "Next step: take Proxmox snapshot of this VM before starting test cycles."
Write-Log "  qm snapshot <VMID> baseline_ready"

exit 0
