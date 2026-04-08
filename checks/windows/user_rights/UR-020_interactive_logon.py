"""
UR-020_interactive_logon.py
----------------------------
SeInteractiveLogonRight controls who can log on locally at the console.
Guests (*S-1-5-32-546) must NOT be in this list.

Check ID : UR-020
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

_FORBIDDEN_SID = "*S-1-5-32-546"  # Guests


@register_check("UR-020")
def check_interactive_logon(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Guests are not permitted local interactive logon."""
    result = base_result(
        connector,
        "UR-020",
        "Local Interactive Logon — Guests Excluded",
        "Verify SeInteractiveLogonRight does not include the Guests group.",
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
$line = ($content | Where-Object { $_ -match '^SeInteractiveLogonRight\s*=' }) | Select-Object -First 1
Write-Output "SeInteractiveLogonRight: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeInteractiveLogonRight:"):
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

        if _FORBIDDEN_SID in sids:
            result.status = STATUS_FAIL
            result.finding = (
                f"Guests (*S-1-5-32-546) are included in SeInteractiveLogonRight. "
                f"Full grant list: {value_part}"
            )
            result.remediation = (
                "Remove Guests from SeInteractiveLogonRight via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Allow log on locally. "
                "Also ensure the Guest account is disabled (see AC-003)."
            )
        else:
            result.status = STATUS_PASS
            result.finding = (
                f"Guests are not permitted local interactive logon. "
                f"Current grant list: {value_part or '(not explicitly configured)'}"
            )
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
