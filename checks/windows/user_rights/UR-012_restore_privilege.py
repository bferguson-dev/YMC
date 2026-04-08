"""
UR-012_restore_privilege.py
----------------------------
SeRestorePrivilege allows bypassing file and directory ACLs during restore,
and can set any valid security principal as the owner of an object.
It should be restricted to Administrators and Backup Operators only.

Check ID : UR-012
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


@register_check("UR-012")
def check_restore_privilege(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeRestorePrivilege is restricted to Administrators and Backup Operators."""
    result = base_result(
        connector,
        "UR-012",
        "Restore Files and Directories — Restricted",
        "Verify SeRestorePrivilege is granted only to Administrators and Backup Operators.",
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
$line = ($content | Where-Object { $_ -match '^SeRestorePrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeRestorePrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeRestorePrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeRestorePrivilege is not granted (stricter than required)."
            )
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = (
                f"SeRestorePrivilege is restricted to allowed accounts: {value_part}"
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeRestorePrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}."
            )
            result.remediation = (
                "Restrict SeRestorePrivilege to Administrators and Backup Operators via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Restore files and directories."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
