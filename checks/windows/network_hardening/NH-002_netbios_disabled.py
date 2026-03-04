"""
NH-002_netbios_disabled.py
--------------------------
NetBIOS name broadcasts can be intercepted by attackers using Responder/Inveigh
to capture NTLM credentials. Disabling removes this attack surface.

Check ID : NH-002
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.5
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


@register_check("NH-002")
def check_netbios_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies NetBIOS over TCP/IP is disabled on all network adapters."""
    result = base_result(
        connector,
        "NH-002",
        "NetBIOS over TCP/IP Disabled",
        "Verify NetBIOS over TCP/IP is disabled to prevent NBT-NS poisoning attacks.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- NetBIOS over TCP/IP per adapter ---"
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$issues = @()
foreach ($a in $adapters) {
    # TcpipNetbiosOptions: 0=default, 1=enabled, 2=disabled
    $nbios = $a.TcpipNetbiosOptions
    Write-Output "  Adapter: $($a.Description) | NetBIOS option: $nbios  (2=disabled)"
    if ($nbios -ne 2) { $issues += $a.Description }
}
if ($issues.Count -eq 0) { Write-Output "STATUS: COMPLIANT" }
else { Write-Output "STATUS: NON-COMPLIANT - $($issues.Count) adapter(s) have NetBIOS enabled" }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        if "STATUS: COMPLIANT" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "NetBIOS over TCP/IP is disabled on all network adapters."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "NetBIOS over TCP/IP is enabled on one or more adapters. Vulnerable to NBT-NS poisoning attacks."
            result.remediation = (
                "Disable NetBIOS on each adapter: Network connections > Adapter Properties > "
                "TCP/IP Properties > Advanced > WINS tab > Disable NetBIOS over TCP/IP. "
                "Or via DHCP server option 001 for domain environments."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
