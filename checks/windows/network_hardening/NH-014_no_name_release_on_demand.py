"""
NH-014_no_name_release_on_demand.py
-------------------------------------
When NoNameReleaseOnDemand is not set, a system will release its NetBIOS name
in response to name release requests, allowing attackers to cause denial of
service or take over the system's NetBIOS name on the network.

Check ID : NH-014
Category : Network Hardening
Framework: NIST SC-7, DISA STIG CAT-II
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


@register_check("NH-014")
def check_no_name_release_on_demand(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies NetBIOS name release on demand is prevented (NoNameReleaseOnDemand=1)."""
    result = base_result(
        connector,
        "NH-014",
        "NetBIOS Name Release Attack Prevention",
        "Verify NoNameReleaseOnDemand=1 to prevent NetBIOS name hijacking.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NoNameReleaseOnDemand' -ErrorAction SilentlyContinue).NoNameReleaseOnDemand
Write-Output "NoNameReleaseOnDemand: $val  (1=protected, 0=vulnerable)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("NoNameReleaseOnDemand:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val == 1:
            result.status = STATUS_PASS
            result.finding = "NetBIOS name release on demand is disabled (NoNameReleaseOnDemand=1). Protected against name hijacking."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"NoNameReleaseOnDemand={val} — system will release its NetBIOS name on request. "
                "An attacker can trigger a denial of service or NetBIOS name hijacking."
            )
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters "
                "NoNameReleaseOnDemand=1 (DWORD) via Group Policy or registry."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
