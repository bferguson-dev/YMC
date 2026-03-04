"""
AC-004_administrator_renamed.py
-------------------------------
Checks whether the built-in Administrator account (SID ending in -500)

Check ID : AC-004
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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-004")
def check_administrator_renamed(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether the built-in Administrator account (SID ending in -500)
    has been renamed from the default 'Administrator' name.
    """
    result = base_result(
        connector,
        "AC-004",
        "Administrator Account Renamed",
        "Verify the built-in Administrator account (RID 500) has been renamed.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
# RID 500 is always the built-in Administrator regardless of rename
$adminSID = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::AccountAdministratorSid, $null
)
$adminAccount = Get-LocalUser | Where-Object { $_.SID -eq $adminSID }
if ($null -eq $adminAccount) {
    Write-Output "INFO: Built-in Administrator account not found (may have been deleted or is domain-joined)."
} elseif ($adminAccount.Name -ne 'Administrator') {
    Write-Output "COMPLIANT: Built-in Administrator account has been renamed."
    Write-Output "  Current Name : $($adminAccount.Name)"
    Write-Output "  SID          : $($adminAccount.SID)"
    Write-Output "  Enabled      : $($adminAccount.Enabled)"
} else {
    Write-Output "NON-COMPLIANT: Built-in Administrator account retains default name 'Administrator'."
    Write-Output "  Current Name : $($adminAccount.Name)"
    Write-Output "  SID          : $($adminAccount.SID)"
    Write-Output "  Enabled      : $($adminAccount.Enabled)"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "COMPLIANT" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "Built-in Administrator account has been renamed."
        elif "INFO" in cmd.stdout:
            result.status = STATUS_WARNING
            result.finding = "Built-in Administrator account not found locally — may be domain-managed. Review manually."
            result.remediation = (
                "Confirm domain policy controls the built-in admin account name."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "Built-in Administrator account uses the default name 'Administrator'."
            )
            result.remediation = (
                "Rename via: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Accounts: Rename administrator account'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AC-005 — Local Administrators Group Membership
# ---------------------------------------------------------------------------
