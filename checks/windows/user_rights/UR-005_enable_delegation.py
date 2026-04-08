"""
UR-005_enable_delegation.py
---------------------------
SeEnableDelegationPrivilege allows setting the trusted-for-delegation flag
on user or computer objects in Active Directory. No account should hold this
right on member servers and workstations.

Check ID : UR-005
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


@register_check("UR-005")
def check_enable_delegation(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SeEnableDelegationPrivilege is not granted to any account."""
    result = base_result(
        connector,
        "UR-005",
        "Enable Computer and User Accounts for Delegation — Empty",
        "Verify SeEnableDelegationPrivilege is not granted to any account.",
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
$line = ($content | Where-Object { $_ -match '^SeEnableDelegationPrivilege\s*=' }) | Select-Object -First 1
Write-Output "SeEnableDelegationPrivilege: $line"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        raw_line = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("SeEnableDelegationPrivilege:"):
                raw_line = line.split(":", 1)[1].strip()
                break

        value_part = ""
        if "=" in raw_line:
            value_part = raw_line.split("=", 1)[1].strip()

        if not value_part:
            result.status = STATUS_PASS
            result.finding = (
                "SeEnableDelegationPrivilege is not granted to any account."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"SeEnableDelegationPrivilege is granted to: {value_part}. "
                "This right should not be assigned on member servers or workstations."
            )
            result.remediation = (
                "Remove SeEnableDelegationPrivilege from all accounts via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > User Rights Assignment > "
                "Enable computer and user accounts to be trusted for delegation."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
