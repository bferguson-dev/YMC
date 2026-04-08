"""
UR-010_remote_interactive_logon.py
------------------------------------
SeRemoteInteractiveLogonRight (Allow log on through Remote Desktop Services)
should only contain Administrators and Remote Desktop Users. Any other
non-service SID is a policy violation.

Check ID : UR-010
Category : User Rights Assignment
Framework: NIST AC-6, DISA STIG CAT-II
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

_ALLOWED_SIDS = {
    "*S-1-5-32-544",  # Administrators
    "*S-1-5-32-555",  # Remote Desktop Users
}


@register_check("UR-010")
def check_remote_interactive_logon(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeRemoteInteractiveLogonRight is restricted to Admins and RDP Users."""
    result = base_result(
        connector,
        "UR-010",
        "Remote Interactive Logon — Restricted",
        "Verify SeRemoteInteractiveLogonRight contains only Administrators and Remote Desktop Users.",
        "User Rights Assignment",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$tmp = "$env:TEMP\ymc_ur_$(Get-Random).cfg"
secedit /export /cfg $tmp /areas USER_RIGHTS 2>&1 | Out-Null
$content = Get-Content $tmp -ErrorAction SilentlyContinue
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
$line = ($content | Where-Object { $_ -match '^SeRemoteInteractiveLogonRight\s*=' }) | Select-Object -First 1
Write-Output "SeRemoteInteractiveLogonRight: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeRemoteInteractiveLogonRight:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = "SeRemoteInteractiveLogonRight is not configured (no explicit grant — RDP restricted)."
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = f"SeRemoteInteractiveLogonRight is restricted to allowed accounts: {value_part}"
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeRemoteInteractiveLogonRight contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}. "
                "Only Administrators and Remote Desktop Users should have this right."
            )
            result.remediation = (
                "Restrict SeRemoteInteractiveLogonRight to Administrators and Remote Desktop Users "
                "via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > "
                "Allow log on through Remote Desktop Services."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
