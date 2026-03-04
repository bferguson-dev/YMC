"""
NH-001_llmnr_disabled.py
------------------------
LLMNR broadcasts name queries on the local network when DNS fails.
Attackers use tools like Responder to intercept these and capture NTLM credentials.

Check ID : NH-001
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.4
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


@register_check("NH-001")
def check_llmnr_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Link-Local Multicast Name Resolution (LLMNR) is disabled."""
    result = base_result(
        connector,
        "NH-001",
        "LLMNR Disabled",
        "Verify LLMNR is disabled to prevent credential theft via responder attacks.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$llmnr = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
Write-Output "EnableMulticast (LLMNR): $llmnr  (0=disabled/safe, 1=enabled/unsafe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if "EnableMulticast (LLMNR):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if val == 0:
            result.status = STATUS_PASS
            result.finding = "LLMNR is disabled (EnableMulticast=0). Responder-based credential theft attacks are mitigated."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"LLMNR is ENABLED (value: {val}). System is vulnerable to Responder NTLM credential theft."
            result.remediation = (
                "Disable via GPO: Computer Configuration > Administrative Templates > "
                "Network > DNS Client > 'Turn off multicast name resolution'. Set to Enabled."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
