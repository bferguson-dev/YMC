"""
UR-008_deny_remote_interactive_logon.py
----------------------------------------
SeDenyRemoteInteractiveLogonRight prevents accounts from logging on via
Remote Desktop. The Guests group must be explicitly denied remote interactive logon.

Check ID : UR-008
Category : User Rights Assignment
Framework: NIST AC-3, DISA STIG CAT-I
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

_REQUIRED_SID = "*S-1-5-32-546"  # Guests


@register_check("UR-008")
def check_deny_remote_interactive_logon(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Guests are denied remote interactive (RDP) logon."""
    result = base_result(
        connector,
        "UR-008",
        "Deny Remote Interactive Logon — Guests Excluded",
        "Verify SeDenyRemoteInteractiveLogonRight includes the Guests group.",
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
$line = ($content | Where-Object { $_ -match '^SeDenyRemoteInteractiveLogonRight\s*=' }) | Select-Object -First 1
Write-Output "SeDenyRemoteInteractiveLogonRight: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeDenyRemoteInteractiveLogonRight:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        sids = (
            {s.strip() for s in value_part.split(",") if s.strip()}
            if value_part
            else set()
        )

        if _REQUIRED_SID in sids:
            result.status = STATUS_PASS
            result.finding = (
                f"Guests (*S-1-5-32-546) are explicitly denied remote interactive logon. "
                f"Full deny list: {value_part or '(empty)'}"
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"Guests (*S-1-5-32-546) are NOT in SeDenyRemoteInteractiveLogonRight. "
                f"Current deny list: {value_part or '(empty/not configured)'}"
            )
            result.remediation = (
                "Add the Guests group to SeDenyRemoteInteractiveLogonRight via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > "
                "Deny log on through Remote Desktop Services."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
