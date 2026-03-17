"""
AC-021_computer_description.py
-------------------------------
Checks whether the computer description field contains sensitive information.

Check ID : AC-021
Category : Access Control
Framework: NIST AC-22, CIS 2.3.8
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


@register_check("AC-021")
def check_computer_description(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Checks the computer description field for sensitive information disclosure."""
    result = base_result(
        connector,
        "AC-021",
        "Computer Description Field",
        "Verify the computer description does not disclose sensitive system information.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$desc = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'srvcomment' -ErrorAction SilentlyContinue).srvcomment
Write-Output "Computer description: $desc"
$wmi = (Get-WmiObject Win32_OperatingSystem).Description
Write-Output "WMI OS description  : $wmi"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        desc = ""
        wmi_desc = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("Computer description:"):
                desc = line.split(":", 1)[1].strip()
            if line.startswith("WMI OS description  :"):
                wmi_desc = line.split(":", 1)[1].strip()

        risky_keywords = [
            "admin",
            "server",
            "dc",
            "domain",
            "prod",
            "sql",
            "finance",
            "hr",
            "payroll",
            "backup",
            "controller",
        ]
        combined = (desc + " " + wmi_desc).lower()
        flagged = [k for k in risky_keywords if k in combined]

        if not desc and not wmi_desc:
            result.status = STATUS_PASS
            result.finding = (
                "Computer description field is empty - no information disclosure risk."
            )
            result.remediation = ""
        elif flagged:
            result.status = STATUS_WARNING
            result.finding = (
                f"Computer description may disclose sensitive system role: '{desc}'. "
                f"Keywords found: {flagged}. This is visible to unauthenticated network users."
            )
            result.remediation = (
                "Clear the computer description: Set-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                "-Name srvcomment -Value ''. Avoid describing the system role in this field."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"Computer description is set to: '{desc}'. Verify it does not disclose sensitive information."
            result.remediation = "Review description content. Clear if it reveals system role, environment, or ownership."

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
