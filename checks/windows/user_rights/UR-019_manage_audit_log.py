"""
UR-019_manage_audit_log.py
---------------------------
SeSecurityPrivilege (Manage auditing and security log) allows viewing and
clearing the Security log. Only Administrators should hold this right.

Check ID : UR-019
Category : User Rights Assignment
Framework: NIST AU-9, DISA STIG CAT-II
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

_ALLOWED_SIDS = {"*S-1-5-32-544"}  # Administrators


@register_check("UR-019")
def check_manage_audit_log(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeSecurityPrivilege is restricted to Administrators only."""
    result = base_result(
        connector,
        "UR-019",
        "Manage Auditing and Security Log — Administrators Only",
        "Verify SeSecurityPrivilege is granted only to Administrators.",
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
$line = ($content | Where-Object { $_ -match '^SeSecurityPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeSecurityPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeSecurityPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeSecurityPrivilege is not explicitly granted to any account."
            )
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = f"SeSecurityPrivilege is restricted to Administrators only ({value_part})."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeSecurityPrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}."
            )
            result.remediation = (
                "Restrict SeSecurityPrivilege to Administrators only via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Manage auditing and security log."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
