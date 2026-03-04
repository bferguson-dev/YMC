"""
AC-010_rdp_exposure.py
----------------------
Checks whether RDP (port 3389) is enabled and listening, which firewall

Check ID : AC-010
Category : Access Control
Framework: NIST AC-17

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern — no other files need to be modified.
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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-010")
def check_rdp_exposure(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether RDP (port 3389) is enabled and listening, which firewall
    profiles allow inbound RDP, and whether NLA is enforced. A system with
    RDP open to all networks without NLA is a critical finding.
    """
    result = base_result(
        connector,
        "AC-010",
        "RDP Network Exposure",
        "Determine whether RDP is exposed and whether NLA is required.",
        "Access Control",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- RDP Service Status ---"
$rdp = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
Write-Output "TermService Status: $($rdp.Status)"

Write-Output ""
Write-Output "--- RDP Listener (Port 3389) ---"
$listener = netstat -an | Select-String ':3389'
if ($listener) {
    $listener | ForEach-Object { Write-Output $_.Line }
} else {
    Write-Output "Port 3389 is not listening."
}

Write-Output ""
Write-Output "--- RDP Enabled in Registry ---"
$fDenyTS = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
Write-Output "fDenyTSConnections: $fDenyTS  (0 = RDP enabled, 1 = disabled)"

Write-Output ""
Write-Output "--- NLA (Network Level Authentication) ---"
$nla = (Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
Write-Output "UserAuthentication (NLA): $nla  (1 = NLA required, 0 = NLA not required)"

Write-Output ""
Write-Output "--- Firewall Rules Allowing Inbound RDP ---"
$rules = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }
if ($rules) {
    $rules | ForEach-Object {
        Write-Output "Rule: $($_.DisplayName) | Profile: $($_.Profile) | Action: $($_.Action)"
    }
} else {
    Write-Output "No enabled inbound RDP firewall rules found."
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        rdp_enabled = "fDenyTSConnections: 0" in output
        nla_required = "UserAuthentication (NLA): 1" in output
        port_listening = ":3389" in output and "is not listening" not in output

        if not rdp_enabled and not port_listening:
            result.status = STATUS_PASS
            result.finding = (
                "RDP is disabled on this system. Port 3389 is not listening."
            )
        elif rdp_enabled and nla_required:
            result.status = STATUS_WARNING
            result.finding = (
                "RDP is enabled and NLA is enforced. Review firewall rules in raw "
                "evidence to confirm RDP access is restricted to authorized networks only."
            )
            result.remediation = (
                "Ensure RDP firewall rules restrict access to management networks only. "
                "Consider implementing a jump server or VPN for RDP access."
            )
        elif rdp_enabled and not nla_required:
            result.status = STATUS_FAIL
            result.finding = (
                "RDP is enabled WITHOUT Network Level Authentication (NLA). "
                "This exposes the login screen to unauthenticated users on the network."
            )
            result.remediation = (
                "Enable NLA: System Properties > Remote > "
                "'Allow connections only from computers running Remote Desktop with NLA'. "
                "Or via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Remote Desktop Services > Require NLA."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "RDP status could not be conclusively determined. Review raw evidence."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-007 — Advanced Audit Policy (Object Access + Process Creation)
# ---------------------------------------------------------------------------
