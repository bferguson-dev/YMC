"""
NH-015_router_discovery_disabled.py
-------------------------------------
IRDP (Router Discovery) allows the system to automatically discover and use
router advertisements. Attackers can send spoofed IRDP advertisements to
redirect traffic through a malicious host. This should be disabled.

Check ID : NH-015
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


@register_check("NH-015")
def check_router_discovery_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies IRDP router discovery is disabled (PerformRouterDiscovery=0)."""
    result = base_result(
        connector,
        "NH-015",
        "Router Discovery (IRDP) Disabled",
        "Verify PerformRouterDiscovery=0 to prevent IRDP-based traffic redirection.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -ErrorAction SilentlyContinue).PerformRouterDiscovery
Write-Output "PerformRouterDiscovery: $val  (0=disabled/safe, 1/2=enabled/unsafe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("PerformRouterDiscovery:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val == 0:
            result.status = STATUS_PASS
            result.finding = (
                "Router discovery (IRDP) is disabled (PerformRouterDiscovery=0)."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"PerformRouterDiscovery={val} — IRDP is enabled or using default. "
                "Spoofed router advertisements can redirect traffic through an attacker-controlled host."
            )
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                "PerformRouterDiscovery=0 (DWORD) via Group Policy or registry."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
