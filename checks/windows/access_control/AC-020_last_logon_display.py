"""
AC-020_last_logon_display.py
----------------------------
Verifies Windows displays the last interactive logon information at login.

Check ID : AC-020
Category : Access Control
Framework: NIST AC-9, CIS 2.3.7
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


@register_check("AC-020")
def check_last_logon_display(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies last interactive logon information is displayed at login."""
    result = base_result(
        connector,
        "AC-020",
        "Last Interactive Logon Display",
        "Verify last logon time and failed attempts are displayed at login.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$val = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'DisplayLastLogonInfo' -ErrorAction SilentlyContinue).DisplayLastLogonInfo
Write-Output "DisplayLastLogonInfo: $val  (1=display last logon info)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "DisplayLastLogonInfo:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except ValueError:
                    pass
        if val == 1:
            result.status = STATUS_PASS
            result.finding = "Last interactive logon information is displayed at login (DisplayLastLogonInfo=1)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"Last logon information is NOT displayed at login (value: {val}). Users cannot detect unauthorized access."
            result.remediation = (
                "Enable via GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Interactive logon: Display user information when the session is locked' and "
                "set DisplayLastLogonInfo=1 in "
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
