"""
NH-009_syn_attack_protection.py
-------------------------------
SYN flood attacks consume connection resources by sending many SYN packets without
completing the handshake. Windows SynAttackProtect mitigates this.

Check ID : NH-009
Category : Network Hardening
Framework: NIST SC-5, CIS 18.4.3
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


@register_check("NH-009")
def check_syn_attack_protection(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies TCP SYN flood attack protection is enabled."""
    result = base_result(
        connector,
        "NH-009",
        "TCP SYN Attack Protection",
        "Verify SYN attack protection is enabled to defend against TCP SYN flood attacks.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$syn = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'SynAttackProtect' -ErrorAction SilentlyContinue).SynAttackProtect
Write-Output "SynAttackProtect: $syn  (1=enabled, 2=more protective)"
$thresh1 = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'TcpMaxPortsExhausted' -ErrorAction SilentlyContinue).TcpMaxPortsExhausted
$thresh2 = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'TcpMaxHalfOpen' -ErrorAction SilentlyContinue).TcpMaxHalfOpen
Write-Output "TcpMaxPortsExhausted: $thresh1"
Write-Output "TcpMaxHalfOpen      : $thresh2"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("SynAttackProtect:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val in (1, 2):
            result.status = STATUS_PASS
            result.finding = (
                f"SYN attack protection is enabled (SynAttackProtect={val})."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"SYN attack protection is NOT enabled (value: {val}). System is vulnerable to TCP SYN flood attacks."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                "SynAttackProtect=1 or 2 (DWORD)."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
