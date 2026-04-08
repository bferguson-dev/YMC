"""
UR-009_network_logon_no_everyone.py
------------------------------------
SeNetworkLogonRight controls who can access the computer from the network.
The Everyone group (*S-1-1-0) must NOT be in this list on hardened systems.

Check ID : UR-009
Category : User Rights Assignment
Framework: NIST AC-3, DISA STIG CAT-I
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

_FORBIDDEN_SID = "*S-1-1-0"  # Everyone


@register_check("UR-009")
def check_network_logon_no_everyone(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Everyone (*S-1-1-0) is not granted network logon rights."""
    result = base_result(
        connector,
        "UR-009",
        "Network Logon — Everyone Not Allowed",
        "Verify SeNetworkLogonRight does not include the Everyone group.",
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
$line = ($content | Where-Object { $_ -match '^SeNetworkLogonRight\s*=' }) | Select-Object -First 1
Write-Output "SeNetworkLogonRight: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeNetworkLogonRight:"):
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
                f"Everyone (*S-1-1-0) is included in SeNetworkLogonRight. "
                f"Full grant list: {value_part}"
            )
            result.remediation = (
                "Remove Everyone from SeNetworkLogonRight via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > "
                "Access this computer from the network. "
                "Restrict to Administrators, Authenticated Users, and specific service accounts."
            )
        else:
            result.status = STATUS_PASS
            result.finding = (
                f"Everyone is not in SeNetworkLogonRight. "
                f"Current grant list: {value_part or '(not configured/default)'}"
            )
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
