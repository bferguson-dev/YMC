"""
IA-006_kerberos_service_ticket.py
-----------------------------------
The maximum Kerberos service ticket lifetime (MaxServiceAge) should not exceed
600 minutes (10 hours). Longer service ticket lifetimes extend replay attack windows.

Check ID : IA-006
Category : Identification & Authentication
Framework: NIST IA-8, CIS 2.3.17.2
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

_MAX_MINUTES = 600


@register_check("IA-006")
def check_kerberos_service_ticket(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies maximum Kerberos service ticket lifetime does not exceed 600 minutes."""
    result = base_result(
        connector,
        "IA-006",
        "Kerberos Maximum Service Ticket Lifetime",
        f"Verify Kerberos MaxServiceAge is <= {_MAX_MINUTES} minutes.",
        "Identification & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxServiceAge' -ErrorAction SilentlyContinue).MaxServiceAge
Write-Output "MaxServiceAge: $val"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("MaxServiceAge:"):
                v = line.split(":", 1)[1].strip()
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val is None:
            result.status = STATUS_PASS
            result.finding = (
                f"MaxServiceAge registry key is not set. "
                f"Windows default is {_MAX_MINUTES} minutes — compliant."
            )
            result.remediation = ""
        elif val <= _MAX_MINUTES:
            result.status = STATUS_PASS
            result.finding = (
                f"MaxServiceAge={val} minutes, within the {_MAX_MINUTES}-minute limit."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"MaxServiceAge={val} minutes exceeds the maximum of {_MAX_MINUTES} minutes. "
                "Long-lived service tickets extend replay attack windows."
            )
            result.remediation = (
                f"Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters "
                f"MaxServiceAge={_MAX_MINUTES} (DWORD, value in minutes), or configure via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Account Policies > Kerberos Policy > Maximum lifetime for service ticket."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
