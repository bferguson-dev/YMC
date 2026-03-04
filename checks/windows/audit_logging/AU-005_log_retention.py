"""
AU-005_log_retention.py
-----------------------
Checks the log retention mode for Security, System, and Application logs.

Check ID : AU-005
Category : Audit & Logging
Framework: NIST AU-11

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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AU-005")
def check_log_retention(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks the log retention mode for Security, System, and Application logs.
    Logs set to 'Overwrite as needed' with no archiving are a compliance risk.
    """
    result = base_result(
        connector,
        "AU-005",
        "Event Log Retention Configuration",
        "Verify event logs are configured to retain or archive rather than silently overwrite.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Event Log Retention Modes ---"
$logs = @('Security', 'System', 'Application')
$issues = @()
foreach ($logName in $logs) {
    $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if ($log) {
        Write-Output "$logName Log Mode: $($log.LogMode)"
        if ($log.LogMode -eq 'Circular') {
            $issues += $logName
        }
    }
}
if ($issues.Count -eq 0) {
    Write-Output "RETENTION_STATUS: PASS"
} else {
    Write-Output "RETENTION_STATUS: WARNING - Circular logging on: $($issues -join ', ')"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "RETENTION_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "Event logs are configured to retain or archive rather than circular overwrite."
        elif "RETENTION_STATUS: WARNING" in cmd.stdout:
            result.status = STATUS_WARNING
            result.finding = (
                "One or more event logs use Circular mode (overwrite when full). "
                "This may cause log gaps during high-activity periods. "
                "Consider log forwarding to a SIEM to compensate."
            )
            result.remediation = (
                "Configure log forwarding to a centralized SIEM or syslog server "
                "so that log data is preserved before local circular overwrite occurs."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Could not determine log retention mode. Review raw evidence."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-006 — Remote Log Forwarding
# ---------------------------------------------------------------------------
