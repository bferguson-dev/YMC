"""
NH-011_ntlm_audit.py
---------------------
Verifies NTLM usage auditing is enabled.

Check ID : NH-011
Category : Network Hardening
Framework: NIST AU-2, CIS 2.3.11
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("NH-011")
def check_ntlm_audit(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies NTLM authentication auditing is enabled to detect legacy auth usage."""
    result = base_result(
        connector,
        "NH-011",
        "NTLM Authentication Auditing",
        "Verify NTLM authentication attempts are audited to detect legacy authentication usage.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$incoming = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
$outgoing = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
$domain   = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -Name 'AuditNTLMInDomain' -ErrorAction SilentlyContinue).AuditNTLMInDomain
Write-Output "AuditReceivingNTLMTraffic : $incoming  (1=audit incoming, 2=deny+audit)"
Write-Output "RestrictSendingNTLMTraffic: $outgoing  (1=audit outgoing)"
Write-Output "AuditNTLMInDomain         : $domain   (1=audit domain NTLM)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        incoming = None
        outgoing = None
        for line in cmd.stdout.splitlines():
            if "AuditReceivingNTLMTraffic :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    incoming = int(v)
                except ValueError:
                    pass
            if "RestrictSendingNTLMTraffic:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    outgoing = int(v)
                except ValueError:
                    pass

        if incoming in (1, 2) or outgoing in (1, 2):
            result.status = STATUS_PASS
            result.finding = (
                f"NTLM auditing is enabled (incoming={incoming}, outgoing={outgoing})."
            )
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"NTLM authentication auditing is not configured (incoming={incoming}, outgoing={outgoing}). Legacy NTLM usage cannot be detected."
            result.remediation = (
                "Enable NTLM auditing: Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0 "
                "AuditReceivingNTLMTraffic=1 and RestrictSendingNTLMTraffic=1. "
                "Review Event ID 4776 (NTLM auth) and 8001-8004 (NTLM restriction events)."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
