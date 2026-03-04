"""
SI-003_patch_level.py
---------------------
Retrieves the current OS build, version, last installed hotfix date,

Check ID : SI-003
Category : System Integrity
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


@register_check("SI-003")
def check_patch_level(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Retrieves the current OS build, version, last installed hotfix date,
    and the count of pending updates if determinable.
    """
    result = base_result(
        connector,
        "SI-003",
        "OS Patch Level",
        "Retrieve OS version, build number, last update date, and pending hotfixes.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Operating System and Patch Information ---"
$os = Get-CimInstance Win32_OperatingSystem
Write-Output "OS Caption          : $($os.Caption)"
Write-Output "OS Version          : $($os.Version)"
Write-Output "OS Build            : $($os.BuildNumber)"
Write-Output "Install Date        : $($os.InstallDate)"
Write-Output "Last Boot           : $($os.LastBootUpTime)"
Write-Output "Service Pack        : $($os.ServicePackMajorVersion).$($os.ServicePackMinorVersion)"

# Last installed hotfix
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue
if ($hotfixes) {
    $latest = $hotfixes | Select-Object -First 1
    Write-Output "Last Hotfix         : $($latest.HotFixID)"
    Write-Output "Last Hotfix Date    : $($latest.InstalledOn)"
    Write-Output "Total Hotfixes      : $($hotfixes.Count)"

    $daysSinceUpdate = ((Get-Date) - [datetime]$latest.InstalledOn).Days
    Write-Output "Days Since Update   : $daysSinceUpdate"

    if ($daysSinceUpdate -le 60) {
        Write-Output "PATCH_STATUS: PASS - Last update within 60 days"
    } elseif ($daysSinceUpdate -le 90) {
        Write-Output "PATCH_STATUS: WARNING - Last update $daysSinceUpdate days ago"
    } else {
        Write-Output "PATCH_STATUS: FAIL - Last update $daysSinceUpdate days ago (>90 days)"
    }
} else {
    Write-Output "PATCH_STATUS: WARNING - Could not retrieve hotfix history"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "PATCH_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "OS patch level is current — last update within 60 days."
        elif "PATCH_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "OS has not received updates in over 90 days."
            result.remediation = (
                "Immediately apply available Windows updates. "
                "If managed by WSUS/SCCM, verify the system is communicating with the update server. "
                "Run: Install-WindowsUpdate -AcceptAll (requires PSWindowsUpdate module) "
                "or initiate via Software Center/WSUS console."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "Patch status requires review. Update date may be recent but could not be parsed."
            result.remediation = (
                "Review raw evidence for last hotfix date and compare against policy."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# IA-001 / IA-002 / IA-003 — Password Policy
# ---------------------------------------------------------------------------
