"""
NH-008_ip_source_routing.py
---------------------------
IP source routing allows the sender to specify the route a packet takes.
This can be abused to bypass security controls and redirect traffic.

Check ID : NH-008
Category : Network Hardening
Framework: NIST CM-7, CIS 18.4.2
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


@register_check("NH-008")
def check_ip_source_routing_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies IP source routing is disabled."""
    result = base_result(
        connector,
        "NH-008",
        "IP Source Routing Disabled",
        "Verify IP source routing is disabled to prevent traffic path manipulation.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$sr = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'DisableIPSourceRouting' -ErrorAction SilentlyContinue).DisableIPSourceRouting
Write-Output "DisableIPSourceRouting: $sr  (2=discard source routed packets/safe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "DisableIPSourceRouting:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 2:
            result.status = STATUS_PASS
            result.finding = "IP source routing is disabled (DisableIPSourceRouting=2). Source-routed packets are discarded."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"IP source routing is not fully disabled (value: {val}). Traffic can be redirected by an attacker."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                "DisableIPSourceRouting=2 (DWORD)."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
