"""
UR-011_backup_privilege.py
--------------------------
SeBackupPrivilege allows bypassing file and directory ACLs during backup.
It should be restricted to Administrators and Backup Operators only.

Check ID : UR-011
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
    "*S-1-5-32-551",  # Backup Operators
}


@register_check("UR-011")
def check_backup_privilege(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeBackupPrivilege is restricted to Administrators and Backup Operators."""
    result = base_result(
        connector,
        "UR-011",
        "Back Up Files and Directories — Restricted",
        "Verify SeBackupPrivilege is granted only to Administrators and Backup Operators.",
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
$line = ($content | Where-Object { $_ -match '^SeBackupPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeBackupPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeBackupPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeBackupPrivilege is not granted (stricter than required)."
            )
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = (
                f"SeBackupPrivilege is restricted to allowed accounts: {value_part}"
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeBackupPrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}."
            )
            result.remediation = (
                "Restrict SeBackupPrivilege to Administrators and Backup Operators via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Back up files and directories."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
