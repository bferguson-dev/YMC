"""
SR-001_vss_restore_points.py
----------------------------
Ransomware typically deletes shadow copies before encrypting files.
Verifying VSS is active and recent confirms recovery options are available.

Check ID : SR-001
Category : Storage & Recovery
Framework: NIST CP-9, CIS 18.9.1
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


@register_check("SR-001")
def check_vss_restore_points(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Volume Shadow Copy Service is running and recent restore points exist."""
    result = base_result(
        connector,
        "SR-001",
        "Volume Shadow Copy / Restore Points",
        "Verify VSS is enabled and recent restore points exist for ransomware recovery.",
        "Storage & Recovery",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$svc = Get-Service VSS -ErrorAction SilentlyContinue
Write-Output "VSS Service Status: $($svc.Status)"
$shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
Write-Output "Shadow copy count: $($shadows.Count)"
if ($shadows.Count -gt 0) {
    $latest = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
    Write-Output "Most recent shadow: $($latest.InstallDate)"
}
$restore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
Write-Output "System restore points: $(@($restore).Count)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        shadow_count = 0
        restore_count = 0
        for line in output.splitlines():
            if "Shadow copy count:" in line:
                try:
                    shadow_count = int(line.split(":", 1)[1].strip())
                except (TypeError, ValueError, IndexError):
                    pass
            if "System restore points:" in line:
                try:
                    restore_count = int(line.split(":", 1)[1].strip())
                except (TypeError, ValueError, IndexError):
                    pass
        if shadow_count > 0 or restore_count > 0:
            result.status = STATUS_PASS
            result.finding = f"VSS is active with {shadow_count} shadow copies and {restore_count} restore points."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = "No Volume Shadow Copies or restore points found. Ransomware recovery options are limited."
            result.remediation = (
                "Enable System Protection: Control Panel > System > System Protection. "
                "Configure VSS via wmic shadowcopy call create Volume='C:\\'. "
                "Consider a backup solution for critical data."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
