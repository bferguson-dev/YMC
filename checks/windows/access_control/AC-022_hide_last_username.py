"""
AC-022_hide_last_username.py
----------------------------
Verifies Windows does not display the last signed-in username at logon.

Check ID : AC-022
Category : Access Control
Framework: CIS 2.3.7
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


@register_check("AC-022")
def check_hide_last_username(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the last signed-in username is not displayed at logon."""
    result = base_result(
        connector,
        "AC-022",
        "Hide Last Signed-in Username",
        "Verify Windows does not display the last signed-in username at logon.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$val = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'DontDisplayLastUserName' -ErrorAction SilentlyContinue).DontDisplayLastUserName
if ($null -eq $val) {
    Write-Output "DontDisplayLastUserName: <not set>  (1=do not display last username)"
} else {
    Write-Output "DontDisplayLastUserName: $val  (1=do not display last username)"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "DontDisplayLastUserName:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 1:
            result.status = STATUS_PASS
            result.finding = "Windows is configured not to display the last signed-in username (DontDisplayLastUserName=1)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "Windows may display the last signed-in username at logon "
                f"(DontDisplayLastUserName={val})."
            )
            result.remediation = (
                "Enable via GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Interactive logon: Do not display last user name', or set "
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
                "DontDisplayLastUserName=1."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
