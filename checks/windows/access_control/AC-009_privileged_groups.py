"""
AC-009_privileged_groups.py
---------------------------
Enumerates membership of high-privilege local groups beyond Administrators:

Check ID : AC-009
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


@register_check("AC-009")
def check_privileged_groups(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Enumerates membership of high-privilege local groups beyond Administrators:
    Backup Operators, Remote Desktop Users, Power Users, Network Configuration
    Operators, and Hyper-V Administrators. Flags any with unexpected members.
    """
    result = base_result(
        connector,
        "AC-009",
        "Privileged Group Membership Review",
        "Enumerate high-privilege local group membership beyond local Administrators.",
        "Access Control",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$groups = @(
    'Backup Operators',
    'Remote Desktop Users',
    'Power Users',
    'Network Configuration Operators',
    'Hyper-V Administrators',
    'Event Log Readers',
    'Remote Management Users'
)

foreach ($groupName in $groups) {
    $group = Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue
    if ($null -eq $group) {
        Write-Output "GROUP: $groupName | STATUS: Does not exist on this system"
        continue
    }
    $members = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
    if ($null -eq $members -or $members.Count -eq 0) {
        Write-Output "GROUP: $groupName | MEMBERS: None"
    } else {
        Write-Output "GROUP: $groupName | MEMBERS: $($members.Count)"
        $members | ForEach-Object {
            Write-Output "  - $($_.Name) | Type: $($_.ObjectClass) | Source: $($_.PrincipalSource)"
        }
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        result.status = STATUS_WARNING
        result.finding = (
            "Privileged group membership enumerated. Human review required to "
            "confirm all members have documented business justification."
        )
        result.remediation = (
            "Review each group in raw evidence. Remove accounts that lack a "
            "documented business need. Apply least-privilege — prefer specific "
            "delegated roles over broad group membership."
        )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AC-010 — RDP Network Exposure
# ---------------------------------------------------------------------------
