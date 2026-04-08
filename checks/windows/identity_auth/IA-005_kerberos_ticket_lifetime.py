"""
IA-005_kerberos_ticket_lifetime.py
------------------------------------
The maximum Kerberos ticket lifetime (MaxTicketAge) should not exceed 10 hours.
Longer ticket lifetimes extend the window for pass-the-ticket attacks using
stolen Kerberos TGTs.

Check ID : IA-005
Category : Identification & Authentication
Framework: NIST IA-8, CIS 2.3.17.1
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

_MAX_HOURS = 10


@register_check("IA-005")
def check_kerberos_ticket_lifetime(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies maximum Kerberos ticket lifetime does not exceed 10 hours."""
    result = base_result(
        connector,
        "IA-005",
        "Kerberos Maximum Ticket Lifetime",
        f"Verify Kerberos MaxTicketAge is <= {_MAX_HOURS} hours.",
        "Identification & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxTicketAge' -ErrorAction SilentlyContinue).MaxTicketAge
Write-Output "MaxTicketAge: $val"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("MaxTicketAge:"):
                v = line.split(":", 1)[1].strip()
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val is None:
            result.status = STATUS_PASS
            result.finding = (
                f"MaxTicketAge registry key is not set. "
                f"Windows default is {_MAX_HOURS} hours — compliant."
            )
            result.remediation = ""
        elif val <= _MAX_HOURS:
            result.status = STATUS_PASS
            result.finding = f"MaxTicketAge={val} hours, which is within the {_MAX_HOURS}-hour limit."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"MaxTicketAge={val} hours exceeds the maximum of {_MAX_HOURS} hours. "
                "Long-lived TGTs extend the window for pass-the-ticket attacks."
            )
            result.remediation = (
                f"Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters "
                f"MaxTicketAge={_MAX_HOURS} (DWORD, value in hours), or configure via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Account Policies > Kerberos Policy > Maximum lifetime for user ticket."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
