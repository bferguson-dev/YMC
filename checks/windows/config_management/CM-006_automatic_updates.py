"""
CM-006_automatic_updates.py
---------------------------
Verifies that Windows Update is configured — either automatic updates

Check ID : CM-006
Category : Config Management
Framework: NIST SI-2

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern — no other files need to be modified.
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("CM-006")
def check_automatic_updates(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Verifies that Windows Update is configured — either automatic updates
    or a WSUS/SCCM policy that manages patching centrally.
    """
    result = base_result(
        connector,
        "CM-006",
        "Automatic Updates / Patch Management",
        "Verify Windows Update is configured for automatic or centrally managed patching.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Windows Update Configuration ---"
$wuPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU'
$wuPath2 = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update'

# Check for WSUS configuration
$wsusServer = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' `
               -Name 'WUServer' -ErrorAction SilentlyContinue).WUServer
if ($wsusServer) {
    Write-Output "WSUS Server Configured    : $wsusServer"
    Write-Output "UPDATE_STATUS: PASS - WSUS/centralized patch management is configured"
} else {
    Write-Output "WSUS Server               : Not configured"
}

# Check auto update settings
if (Test-Path $wuPath) {
    $auOptions = (Get-ItemProperty $wuPath -Name 'AUOptions' -ErrorAction SilentlyContinue).AUOptions
    $noAutoUpdate = (Get-ItemProperty $wuPath -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate
    Write-Output "AUOptions                 : $auOptions (2=Notify,3=AutoDownload,4=AutoInstall)"
    Write-Output "NoAutoUpdate              : $noAutoUpdate (0=Enabled,1=Disabled)"

    if ($noAutoUpdate -eq 1) {
        Write-Output "UPDATE_STATUS: FAIL - Automatic updates are explicitly DISABLED"
    } elseif ($auOptions -ge 3) {
        Write-Output "UPDATE_STATUS: PASS - Auto-download or auto-install is configured"
    } else {
        Write-Output "UPDATE_STATUS: WARNING - Updates notify only - manual action required"
    }
} else {
    # Check Windows Update service state
    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    Write-Output "Windows Update Service    : $($wuSvc.Status) / $($wuSvc.StartType)"
    Write-Output "UPDATE_STATUS: WARNING - No explicit policy found, check manually"
}

# Show last update date
$lastUpdate = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
Write-Output "Last Successful Update    : $lastUpdate"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "UPDATE_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "Patch management is configured (WSUS or automatic updates)."
            )
        elif "UPDATE_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "Automatic updates are explicitly disabled with no WSUS alternative detected."
            result.remediation = (
                "Enable automatic updates or configure WSUS/SCCM for managed patching. "
                "Do not leave systems without a patch management mechanism. "
                "Re-enable Windows Update service: Set-Service wuauserv -StartupType Automatic"
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "Update configuration could not be definitively confirmed. Review raw evidence."
            result.remediation = (
                "Confirm patch management policy is applied via GPO or SCCM/Intune."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# SI-001 / SI-002 — Antivirus / EDR Status and Definitions
# ---------------------------------------------------------------------------
