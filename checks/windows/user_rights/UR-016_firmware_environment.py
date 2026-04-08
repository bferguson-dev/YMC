"""
UR-016_firmware_environment.py
-------------------------------
SeSystemEnvironmentPrivilege allows modifying firmware/NVRAM environment
variables. Exploitation can bypass Secure Boot. Administrators only.

Check ID : UR-016
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

_ALLOWED_SIDS = {"*S-1-5-32-544"}  # Administrators


@register_check("UR-016")
def check_firmware_environment(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeSystemEnvironmentPrivilege is restricted to Administrators only."""
    result = base_result(
        connector,
        "UR-016",
        "Modify Firmware Environment Values — Administrators Only",
        "Verify SeSystemEnvironmentPrivilege is granted only to Administrators.",
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
$line = ($content | Where-Object { $_ -match '^SeSystemEnvironmentPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeSystemEnvironmentPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeSystemEnvironmentPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeSystemEnvironmentPrivilege is not granted to any account."
            )
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = f"SeSystemEnvironmentPrivilege is restricted to Administrators only ({value_part})."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeSystemEnvironmentPrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}."
            )
            result.remediation = (
                "Restrict SeSystemEnvironmentPrivilege to Administrators only via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > "
                "Modify firmware environment values."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
