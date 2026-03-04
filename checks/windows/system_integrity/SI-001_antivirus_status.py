"""
SI-001_antivirus_status.py
--------------------------
Checks whether Windows Defender or a third-party AV/EDR product is

Check ID : SI-001, SI-002
Category : System Integrity
Framework: NIST SI-3

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


@register_check("SI-001", "SI-002", dedup_group="antivirus")
def check_antivirus_status(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether Windows Defender or a third-party AV/EDR product is
    running and whether definitions are current.
    """
    result = base_result(
        connector,
        "SI-001",
        "Antivirus / EDR Running",
        "Verify antivirus or EDR protection is active and definitions are current.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Antivirus / Security Product Status ---"

# Check Windows Defender
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defender) {
    Write-Output "Windows Defender:"
    Write-Output "  Antivirus Enabled         : $($defender.AntivirusEnabled)"
    Write-Output "  Real-Time Protection      : $($defender.RealTimeProtectionEnabled)"
    Write-Output "  Signature Version         : $($defender.AntivirusSignatureVersion)"
    Write-Output "  Signature Last Updated    : $($defender.AntivirusSignatureLastUpdated)"
    Write-Output "  Quick Scan Last Run       : $($defender.QuickScanEndTime)"

    $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    Write-Output "  Signature Age (Days)      : $sigAge"

    if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled -and $sigAge -le 3) {
        Write-Output "AV_STATUS: PASS"
    } elseif (-not $defender.AntivirusEnabled) {
        Write-Output "AV_STATUS: FAIL - Windows Defender is disabled"
    } elseif ($sigAge -gt 3) {
        Write-Output "AV_STATUS: WARNING - Signatures are $sigAge days old (threshold: 3 days)"
    } else {
        Write-Output "AV_STATUS: WARNING - Review Defender status"
    }
} else {
    # Check for third-party AV via WMI
    $avProducts = Get-CimInstance -Namespace 'root\\SecurityCenter2' `
        -ClassName 'AntiVirusProduct' -ErrorAction SilentlyContinue
    if ($avProducts) {
        Write-Output "Third-Party AV Products:"
        $avProducts | ForEach-Object {
            $state = switch ($_.ProductState) {
                266240 { "Enabled, Up-to-date" }
                266256 { "Enabled, Out-of-date" }
                393216 { "Disabled, Up-to-date" }
                393232 { "Disabled, Out-of-date" }
                default { "State code: $($_.ProductState)" }
            }
            Write-Output "  $($_.DisplayName) | State: $state"
        }
        Write-Output "AV_STATUS: PASS - Third-party AV detected"
    } else {
        Write-Output "AV_STATUS: FAIL - No AV product detected"
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "AV_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "Antivirus/EDR protection is active with current definitions."
            )
        elif "AV_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = (
                "No active antivirus protection detected, or protection is disabled."
            )
            result.remediation = (
                "Ensure antivirus or EDR is installed, enabled, and running. "
                "For Windows Defender: Set-MpPreference -DisableRealtimeMonitoring $false\n"
                "For enterprise environments, verify EDR agent (CrowdStrike, SentinelOne, etc.) is installed."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "AV status requires review — definitions may be outdated. See raw evidence."
            result.remediation = "Update antivirus signatures and verify real-time protection is enabled."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# SI-003 — OS Patch Level / Last Update Date
# ---------------------------------------------------------------------------
