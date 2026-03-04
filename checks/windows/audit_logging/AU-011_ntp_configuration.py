"""
AU-011_ntp_configuration.py
---------------------------
Accurate time is required for log correlation, certificate validation, and
Kerberos authentication. Unsynchronized clocks break audit trails.

Check ID : AU-011
Category : Audit & Logging
Framework: NIST AU-8, PCI DSS 10.6
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


@register_check("AU-011")
def check_ntp_configuration(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies NTP is configured and time synchronization is active."""
    result = base_result(
        connector,
        "AU-011",
        "NTP / Time Synchronization",
        "Verify time synchronization is configured to an authoritative source.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$w32tm = w32tm /query /status 2>&1
Write-Output $w32tm
$source = w32tm /query /source 2>&1
Write-Output "Time source: $source"
$svc = Get-Service W32Time -ErrorAction SilentlyContinue
Write-Output "W32Time service: $($svc.Status) / $($svc.StartType)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        svc_running = "running" in output.lower()
        bad_source = (
            "local cmos clock" in output.lower() or "free-running" in output.lower()
        )
        if svc_running and not bad_source:
            result.status = STATUS_PASS
            result.finding = (
                "W32Time is running and synchronized to an external time source."
            )
            result.remediation = ""
        elif bad_source:
            result.status = STATUS_FAIL
            result.finding = "Time synchronization is using the local CMOS clock only — not synchronized to an authoritative source."
            result.remediation = (
                "Configure NTP: w32tm /config /syncfromflags:manual /manualpeerlist:'time.windows.com' /update. "
                "Or via GPO: Computer Configuration > Administrative Templates > System > Windows Time Service."
            )
        elif not svc_running:
            result.status = STATUS_FAIL
            result.finding = (
                "W32Time service is not running. Time synchronization is inactive."
            )
            result.remediation = "Start W32Time: Start-Service W32Time; Set-Service W32Time -StartupType Automatic."
        else:
            result.status = STATUS_WARNING
            result.finding = "Could not fully verify NTP configuration. Review w32tm /query /status output."
            result.remediation = (
                "Run w32tm /query /status to check synchronization state."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
