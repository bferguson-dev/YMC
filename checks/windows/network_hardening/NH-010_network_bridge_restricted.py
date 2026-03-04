"""
NH-010_network_bridge_restricted.py
-----------------------------------
Network bridges can be used to bypass network segmentation controls by
bridging separate network segments without authorization.

Check ID : NH-010
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.2
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


@register_check("NH-010")
def check_network_bridge_restricted(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies non-administrators cannot create network bridges."""
    result = base_result(
        connector,
        "NH-010",
        "Network Bridge Creation Restricted",
        "Verify network bridge creation is restricted to administrators only.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$bridge = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' -Name 'NC_AllowNetBridge_NLA' -ErrorAction SilentlyContinue).NC_AllowNetBridge_NLA
Write-Output "NC_AllowNetBridge_NLA: $bridge  (0=restricted/safe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "NC_AllowNetBridge_NLA:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 0:
            result.status = STATUS_PASS
            result.finding = (
                "Network bridge creation is restricted (NC_AllowNetBridge_NLA=0)."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"Network bridge creation is NOT restricted (value: {val}). Users may bridge network segments."
            result.remediation = (
                "Restrict via GPO: Computer Configuration > Administrative Templates > "
                "Network > Network Connections > 'Prohibit installation and configuration of Network Bridge on your DNS domain network'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
