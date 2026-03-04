"""
AC-003_guest_account_disabled.py
--------------------------------
Verifies the built-in Guest account is disabled.

Check ID : AC-003
Category : Access Control
Framework: NIST AC-2, CIS 1.1

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
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-003")
def check_guest_account_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the built-in Guest account is disabled."""
    result = base_result(
        connector,
        "AC-003",
        "Guest Account Disabled",
        "Verify the built-in Guest account is disabled on this system.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
if ($null -eq $guest) {
    Write-Output "COMPLIANT: Guest account does not exist on this system."
} elseif ($guest.Enabled -eq $false) {
    Write-Output "COMPLIANT: Guest account exists but is disabled."
    Write-Output "  Account Name : $($guest.Name)"
    Write-Output "  Enabled      : $($guest.Enabled)"
    Write-Output "  Description  : $($guest.Description)"
} else {
    Write-Output "NON-COMPLIANT: Guest account is ENABLED."
    Write-Output "  Account Name : $($guest.Name)"
    Write-Output "  Enabled      : $($guest.Enabled)"
    Write-Output "  Last Logon   : $($guest.LastLogon)"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "COMPLIANT" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "Guest account is disabled or does not exist."
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "Built-in Guest account is enabled — unauthorized access risk."
            )
            result.remediation = (
                "Disable the Guest account: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Accounts: Guest account status' = Disabled."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AC-004 — Administrator Account Renamed
# ---------------------------------------------------------------------------
