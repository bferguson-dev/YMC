"""
SV-004_snmp_disabled.py
-----------------------
SNMP v1 and v2c use community strings (essentially plaintext passwords) for
authentication. Exposed SNMP can leak system info and be used for DoS.

Check ID : SV-004
Category : Services
Framework: NIST CM-7, CIS 5.30
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


@register_check("SV-004")
def check_snmp_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the SNMP service is disabled."""
    result = base_result(
        connector,
        "SV-004",
        "SNMP Service Disabled",
        "Verify SNMP is disabled — it exposes system information and uses weak authentication.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$svc = Get-Service SNMP -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output "SNMP Status   : $($svc.Status)"
    Write-Output "SNMP StartType: $($svc.StartType)"
} else { Write-Output "SNMP Status   : not installed" }
$trap = Get-Service SNMPTRAP -ErrorAction SilentlyContinue
if ($trap) { Write-Output "SNMPTRAP: $($trap.Status) / $($trap.StartType)" }
else { Write-Output "SNMPTRAP: not installed" }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        not_installed = "not installed" in output.lower()
        running = "running" in output.lower()
        if not_installed and "running" not in output.lower():
            result.status = STATUS_PASS
            result.finding = "SNMP is not installed on this system."
            result.remediation = ""
        elif running:
            result.status = STATUS_FAIL
            result.finding = "SNMP service is running. SNMP exposes system information and uses weak authentication (v1/v2c)."
            result.remediation = (
                "Disable: Stop-Service SNMP -Force; Set-Service SNMP -StartupType Disabled. "
                "If SNMP v3 monitoring is required, restrict to trusted management stations via firewall."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "SNMP service is installed but stopped/disabled."
            result.remediation = "Consider removing SNMP entirely if not required: Remove Windows Feature SNMP-Service."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
