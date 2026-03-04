"""
AU-008_sysmon.py
----------------
Checks whether Sysinternals Sysmon is installed and running.

Check ID : AU-008
Category : Audit & Logging
Framework: NIST AU-2

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


@register_check("AU-008")
def check_sysmon(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether Sysinternals Sysmon is installed and running.
    Sysmon provides detailed process, network, and file system telemetry
    beyond what native Windows auditing captures. Its presence is a strong
    indicator of a mature security monitoring program.
    """
    result = base_result(
        connector,
        "AU-008",
        "Sysmon Endpoint Telemetry",
        "Check whether Sysmon (System Monitor) is installed and running.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Sysmon Service Status ---"
$sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($null -eq $sysmon) {
    $sysmon = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
}

if ($null -eq $sysmon) {
    Write-Output "SYSMON_NOT_FOUND"
} else {
    Write-Output "Service Name    : $($sysmon.Name)"
    Write-Output "Display Name    : $($sysmon.DisplayName)"
    Write-Output "Status          : $($sysmon.Status)"
    Write-Output "StartType       : $($sysmon.StartType)"
}

Write-Output ""
Write-Output "--- Sysmon Driver ---"
$driver = Get-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue
if ($driver) {
    Write-Output "Driver Status: $($driver.Status)"
} else {
    Write-Output "Sysmon driver not found."
}

Write-Output ""
Write-Output "--- Sysmon Event Log ---"
$log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
if ($log) {
    Write-Output "Sysmon event log exists | Enabled: $($log.IsEnabled) | Records: $($log.RecordCount)"
} else {
    Write-Output "Sysmon event log not found."
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        if "SYSMON_NOT_FOUND" in output:
            result.status = STATUS_WARNING
            result.finding = (
                "Sysmon is not installed on this system. Advanced endpoint telemetry "
                "is not available. Native Windows audit logging is the only event source."
            )
            result.remediation = (
                "Consider deploying Sysmon with a community config (e.g. SwiftOnSecurity "
                "or Olaf Hartong's modular config). Sysmon significantly improves detection "
                "capability for process injection, lateral movement, and persistence techniques."
            )
        elif "Running" in output:
            result.status = STATUS_PASS
            result.finding = "Sysmon is installed and running. Advanced endpoint telemetry is active."
        else:
            result.status = STATUS_FAIL
            result.finding = "Sysmon is installed but the service is NOT running."
            result.remediation = (
                "Start the Sysmon service: Start-Service Sysmon64. "
                "Investigate why the service stopped and ensure it is set to automatic start."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-009 — Windows Defender Advanced Configuration
# ---------------------------------------------------------------------------
