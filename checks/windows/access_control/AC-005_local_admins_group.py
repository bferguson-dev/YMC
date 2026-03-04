"""
AC-005_local_admins_group.py
----------------------------
Enumerates members of the local Administrators group.

Check ID : AC-005
Category : Access Control
Framework: NIST AC-6

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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-005")
def check_local_admins_group(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Enumerates members of the local Administrators group.
    Returns WARNING with full membership list — human review required
    since the tool cannot determine which accounts are authorized.
    """
    result = base_result(
        connector,
        "AC-005",
        "Local Administrators Group Membership",
        "Enumerate local Administrators group members for least-privilege review.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
if ($null -eq $members -or $members.Count -eq 0) {
    Write-Output "INFO: Local Administrators group is empty or could not be read."
} else {
    Write-Output "REVIEW REQUIRED: Local Administrators group contains $($members.Count) member(s):"
    $members | ForEach-Object {
        Write-Output "  - $($_.Name) | Type: $($_.ObjectClass) | PrincipalSource: $($_.PrincipalSource)"
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        # This check always returns WARNING — it collects evidence for human review.
        # The tool cannot determine which accounts are authorized.
        result.status = STATUS_WARNING
        result.finding = (
            "Local Administrators group membership enumerated. "
            "Human review required to confirm all members are authorized."
        )
        result.remediation = (
            "Review the membership list in raw evidence. Remove any accounts that do not "
            "have a documented business need for local administrator access. "
            "Prefer domain group policies over direct local admin assignments."
        )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AC-006 / AC-007 — Account Lockout Policy
# ---------------------------------------------------------------------------
