"""
UR-017_replace_process_token.py
--------------------------------
SeAssignPrimaryTokenPrivilege (Replace a process-level token) should only
be held by Local Service and Network Service. Administrators having this
right is a STIG finding.

Check ID : UR-017
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
    "*S-1-5-19",  # Local Service
    "*S-1-5-20",  # Network Service
}


@register_check("UR-017")
def check_replace_process_token(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeAssignPrimaryTokenPrivilege is held only by Local/Network Service."""
    result = base_result(
        connector,
        "UR-017",
        "Replace a Process Level Token — Service Accounts Only",
        "Verify SeAssignPrimaryTokenPrivilege contains only Local Service and Network Service.",
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
$line = ($content | Where-Object { $_ -match '^SeAssignPrimaryTokenPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeAssignPrimaryTokenPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeAssignPrimaryTokenPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = "SeAssignPrimaryTokenPrivilege is not explicitly configured (system default applies)."
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = f"SeAssignPrimaryTokenPrivilege contains only allowed service accounts: {value_part}"
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeAssignPrimaryTokenPrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}. "
                "Only Local Service (*S-1-5-19) and Network Service (*S-1-5-20) should hold this right."
            )
            result.remediation = (
                "Restrict SeAssignPrimaryTokenPrivilege to Local Service and Network Service "
                "via Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Replace a process level token."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
