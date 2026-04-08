"""
UR-003_lock_memory.py
---------------------
SeLockMemoryPrivilege allows processes to lock pages in physical memory,
preventing them from being paged out. No account should hold this right.

Check ID : UR-003
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


@register_check("UR-003")
def check_lock_memory(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeLockMemoryPrivilege is not granted to any account."""
    result = base_result(
        connector,
        "UR-003",
        "Lock Pages in Memory — Empty",
        "Verify SeLockMemoryPrivilege is not granted to any account.",
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
$line = ($content | Where-Object { $_ -match '^SeLockMemoryPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeLockMemoryPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeLockMemoryPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = "SeLockMemoryPrivilege is not granted to any account."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeLockMemoryPrivilege is granted to: {value_part}. "
                "No account should hold this right."
            )
            result.remediation = (
                "Remove SeLockMemoryPrivilege from all accounts via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Lock pages in memory."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
