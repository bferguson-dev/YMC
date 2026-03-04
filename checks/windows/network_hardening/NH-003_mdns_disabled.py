"""
NH-003_mdns_disabled.py
-----------------------
mDNS can be abused similarly to LLMNR for credential theft via poisoning attacks.
Disabling removes another unnecessary name resolution protocol.

Check ID : NH-003
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.6
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


@register_check("NH-003")
def check_mdns_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies multicast DNS (mDNS) is disabled."""
    result = base_result(
        connector,
        "NH-003",
        "mDNS Disabled",
        "Verify mDNS is disabled to prevent local network name resolution spoofing.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$mdns = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -Name 'EnableMDNS' -ErrorAction SilentlyContinue).EnableMDNS
Write-Output "EnableMDNS: $mdns  (0=disabled, 1 or null=enabled)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "EnableMDNS:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 0:
            result.status = STATUS_PASS
            result.finding = "mDNS is disabled (EnableMDNS=0)."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"mDNS may be enabled (value: {val}). This provides an additional name-poisoning attack surface."
            result.remediation = (
                "Disable mDNS: Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters "
                "EnableMDNS=0 (DWORD). Reboot or restart DNS Client service."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
