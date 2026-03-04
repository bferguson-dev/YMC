"""
NH-007_icmp_redirects_disabled.py
---------------------------------
ICMP redirect messages can be used by attackers to modify the routing table
and redirect traffic through malicious systems.

Check ID : NH-007
Category : Network Hardening
Framework: NIST CM-7, CIS 18.4.1
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


@register_check("NH-007")
def check_icmp_redirects_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies ICMP redirect processing is disabled to prevent routing table manipulation."""
    result = base_result(
        connector,
        "NH-007",
        "ICMP Redirects Disabled",
        "Verify ICMP redirects are disabled to prevent routing table hijacking.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$redir = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'EnableICMPRedirect' -ErrorAction SilentlyContinue).EnableICMPRedirect
Write-Output "EnableICMPRedirect: $redir  (0=disabled/safe, 1=enabled/unsafe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "EnableICMPRedirect:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 0:
            result.status = STATUS_PASS
            result.finding = "ICMP redirects are disabled (EnableICMPRedirect=0)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"ICMP redirects are enabled (value: {val}). Routing table can be manipulated by attackers."
            result.remediation = (
                "Disable: Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                "EnableICMPRedirect=0 (DWORD)."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
