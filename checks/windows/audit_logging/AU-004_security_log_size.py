"""
AU-004_security_log_size.py
---------------------------
Verifies the Security event log maximum size meets the minimum threshold.

Check ID : AU-004
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
    STATUS_FAIL,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AU-004")
def check_security_log_size(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Verifies the Security event log maximum size meets the minimum threshold.
    Default minimum: 192MB (196608 KB).
    """
    result = base_result(
        connector,
        "AU-004",
        "Security Event Log Minimum Size",
        "Verify Security event log is configured to a minimum size to prevent premature overwrite.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )
    min_size_kb = settings.get("min_security_log_size_kb", 196608)
    min_size_mb = min_size_kb // 1024

    ps_script = f"""
Write-Output "--- Security Event Log Configuration ---"
$log = Get-WinEvent -ListLog 'Security'
$maxSizeKB  = [math]::Round($log.MaximumSizeInBytes / 1KB)
$maxSizeMB  = [math]::Round($log.MaximumSizeInBytes / 1MB)
$currentMB  = [math]::Round($log.FileSize / 1MB)
$retention  = $log.LogMode

Write-Output "Maximum Size (KB)     : $maxSizeKB"
Write-Output "Maximum Size (MB)     : $maxSizeMB"
Write-Output "Current Size (MB)     : $currentMB"
Write-Output "Log Mode              : $retention"
Write-Output "Log File Path         : $($log.LogFilePath)"

if ($maxSizeKB -ge {min_size_kb}) {{
    Write-Output "SIZE_STATUS: PASS - Configured size meets minimum of {min_size_mb}MB"
}} else {{
    Write-Output "SIZE_STATUS: FAIL - Configured size ($maxSizeMB MB) is below minimum {min_size_mb}MB"
}}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "SIZE_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = f"Security event log size meets the minimum {min_size_mb}MB requirement."
        elif "SIZE_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = f"Security event log size is below the required minimum of {min_size_mb}MB."
            result.remediation = (
                f"Increase Security log size to at least {min_size_mb}MB via: "
                "Event Viewer > Windows Logs > Security > Properties, "
                f"or via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Event Log Service > Security > "
                f"'Maximum Log Size' = {min_size_kb} KB."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Could not determine Security log size. Review raw evidence."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-005 — Log Retention Configuration
# ---------------------------------------------------------------------------
