"""
UR-001_act_as_os.py
-------------------
SeTcbPrivilege (Act as part of the operating system) grants unrestricted access
to any resource. No account should hold this right in a hardened environment.

Check ID : UR-001
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


@register_check("UR-001")
def check_act_as_os(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeTcbPrivilege (Act as part of the OS) is granted to no one."""
    result = base_result(
        connector,
        "UR-001",
        "Act as Part of the Operating System — Empty",
        "Verify SeTcbPrivilege is not granted to any account.",
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
$line = ($content | Where-Object { $_ -match '^SeTcbPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeTcbPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeTcbPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        # Extract the value after '='
        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = "SeTcbPrivilege is not granted to any account (empty or not configured)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeTcbPrivilege is granted to: {value_part}. "
                "No account should have this right — it provides unrestricted OS-level access."
            )
            result.remediation = (
                "Remove SeTcbPrivilege from all accounts via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Act as part of the operating system."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
