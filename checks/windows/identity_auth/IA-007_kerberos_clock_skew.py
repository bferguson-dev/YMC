"""
IA-007_kerberos_clock_skew.py
-------------------------------
The maximum Kerberos clock synchronization tolerance (MaxClockSkew) controls
how much time difference is permitted between client and KDC. The default and
maximum recommended value is 5 minutes. A larger tolerance weakens replay
attack prevention.

Check ID : IA-007
Category : Identification & Authentication
Framework: NIST IA-8, CIS 2.3.17.3
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

_MAX_MINUTES = 5


@register_check("IA-007")
def check_kerberos_clock_skew(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies maximum Kerberos clock synchronization tolerance is <= 5 minutes."""
    result = base_result(
        connector,
        "IA-007",
        "Kerberos Maximum Clock Synchronization Tolerance",
        f"Verify Kerberos MaxClockSkew is <= {_MAX_MINUTES} minutes.",
        "Identification & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'MaxClockSkew' -ErrorAction SilentlyContinue).MaxClockSkew
Write-Output "MaxClockSkew: $val"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("MaxClockSkew:"):
                v = line.split(":", 1)[1].strip()
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val is None:
            result.status = STATUS_PASS
            result.finding = (
                f"MaxClockSkew registry key is not set. "
                f"Windows default is {_MAX_MINUTES} minutes — compliant."
            )
            result.remediation = ""
        elif val <= _MAX_MINUTES:
            result.status = STATUS_PASS
            result.finding = (
                f"MaxClockSkew={val} minutes, within the {_MAX_MINUTES}-minute limit."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"MaxClockSkew={val} minutes exceeds the maximum of {_MAX_MINUTES} minutes. "
                "A large clock skew tolerance weakens Kerberos replay attack prevention."
            )
            result.remediation = (
                f"Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters "
                f"MaxClockSkew={_MAX_MINUTES} (DWORD, value in minutes), or configure via Group Policy: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Account Policies > Kerberos Policy > "
                "Maximum tolerance for computer clock synchronization."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
