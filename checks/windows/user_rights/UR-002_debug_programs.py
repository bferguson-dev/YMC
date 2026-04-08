"""
UR-002_debug_programs.py
------------------------
SeDebugPrivilege allows attaching a debugger to any process, including LSASS.
This is the privilege used by Mimikatz. Only Administrators should hold it.

Check ID : UR-002
Category : User Rights Assignment
Framework: NIST AC-6, DISA STIG CAT-I
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

_ALLOWED = {"*S-1-5-32-544"}  # Administrators


@register_check("UR-002")
def check_debug_programs(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeDebugPrivilege is restricted to Administrators only."""
    result = base_result(
        connector,
        "UR-002",
        "Debug Programs — Administrators Only",
        "Verify SeDebugPrivilege is granted only to Administrators.",
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
$line = ($content | Where-Object { $_ -match '^SeDebugPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeDebugPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeDebugPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = "SeDebugPrivilege is not granted to any account (stricter than required)."
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = (
                f"SeDebugPrivilege is restricted to Administrators only ({value_part})."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeDebugPrivilege is granted to unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}. Only Administrators (*S-1-5-32-544) should hold this right."
            )
            result.remediation = (
                "Restrict SeDebugPrivilege to Administrators only via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Debug programs."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
