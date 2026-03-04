"""
CM-003_admin_shares.py
----------------------
Enumerates administrative shares (C$, D$, ADMIN$, IPC$).

Check ID : CM-003
Category : Config Management
Framework: NIST CM-7

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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("CM-003")
def check_admin_shares(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Enumerates administrative shares (C$, D$, ADMIN$, IPC$).
    Returns a WARNING with evidence — human review determines acceptability.
    """
    result = base_result(
        connector,
        "CM-003",
        "Administrative Shares Review",
        "Enumerate administrative shares for review. Presence may be acceptable per business need.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Administrative Shares ---"
$adminShares = Get-SmbShare | Where-Object { $_.Name -match '\\$$' }
if ($adminShares) {
    Write-Output "Administrative shares found ($($adminShares.Count)):"
    $adminShares | ForEach-Object {
        Write-Output "  Share: $($_.Name) | Path: $($_.Path) | Description: $($_.Description)"
    }
    Write-Output "SHARE_STATUS: REVIEW_REQUIRED"
} else {
    Write-Output "SHARE_STATUS: PASS - No administrative shares found."
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "SHARE_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "No administrative shares detected."
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Administrative shares (C$, ADMIN$, etc.) are present. "
                "These are Windows defaults. Review whether they are required."
            )
            result.remediation = (
                "If administrative shares are not required, disable them via registry:\n"
                "  HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\n"
                "  AutoShareServer = 0 (servers), AutoShareWks = 0 (workstations)\n"
                "Note: Some management tools depend on ADMIN$ and IPC$."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-004 — AutoRun / AutoPlay Disabled
# ---------------------------------------------------------------------------
