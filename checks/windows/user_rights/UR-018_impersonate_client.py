"""
UR-018_impersonate_client.py
-----------------------------
SeImpersonatePrivilege allows a program to impersonate a client. Allowed
accounts are Administrators, Local Service, Network Service, and Service.
Any other account holding this right is a policy violation.

Check ID : UR-018
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
    "*S-1-5-19",  # Local Service
    "*S-1-5-20",  # Network Service
    "*S-1-5-6",  # Service
}


@register_check("UR-018")
def check_impersonate_client(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeImpersonatePrivilege is restricted to Admins and service accounts."""
    result = base_result(
        connector,
        "UR-018",
        "Impersonate a Client — Restricted",
        "Verify SeImpersonatePrivilege contains only Administrators, Local Service, Network Service, and Service.",
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
$line = ($content | Where-Object { $_ -match '^SeImpersonatePrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeImpersonatePrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeImpersonatePrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeImpersonatePrivilege is not explicitly granted to any account."
            )
            result.remediation = ""
            return result

        sids = {s.strip() for s in value_part.split(",") if s.strip()}
        unexpected = sids - _ALLOWED_SIDS
        if not unexpected:
            result.status = STATUS_PASS
            result.finding = f"SeImpersonatePrivilege is restricted to allowed accounts: {value_part}"
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeImpersonatePrivilege contains unexpected accounts: {unexpected}. "
                f"Full grant list: {value_part}."
            )
            result.remediation = (
                "Restrict SeImpersonatePrivilege to Administrators, Local Service, "
                "Network Service, and Service via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > Impersonate a client after authentication."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
