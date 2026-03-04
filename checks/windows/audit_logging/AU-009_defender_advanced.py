"""
AU-009_defender_advanced.py
---------------------------
Checks Windows Defender beyond basic on/off status:

Check ID : AU-009
Category : Audit & Logging
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


@register_check("AU-009")
def check_defender_advanced(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks Windows Defender beyond basic on/off status:
    - Tamper protection enabled
    - Cloud-delivered protection enabled
    - Real-time protection enabled
    - Behavior monitoring enabled
    - Antivirus signature currency
    """
    result = base_result(
        connector,
        "AU-009",
        "Windows Defender Advanced Configuration",
        "Verify Defender tamper protection, cloud protection, and real-time monitoring.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Windows Defender Status ---"
$prefs = Get-MpPreference -ErrorAction SilentlyContinue
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($null -eq $status) {
    Write-Output "DEFENDER_UNAVAILABLE: Could not retrieve Defender status."
} else {
    Write-Output "AntivirusEnabled          : $($status.AntivirusEnabled)"
    Write-Output "RealTimeProtectionEnabled : $($status.RealTimeProtectionEnabled)"
    Write-Output "BehaviorMonitorEnabled    : $($status.BehaviorMonitorEnabled)"
    Write-Output "IoavProtectionEnabled     : $($status.IoavProtectionEnabled)"
    Write-Output "TamperProtectionSource    : $($status.TamperProtectionSource)"
    Write-Output "CloudProtectionEnabled    : $($prefs.MAPSReporting)"
    Write-Output "AntivirusSignatureAge     : $($status.AntivirusSignatureAge) days"
    Write-Output "AntivirusSignatureVersion : $($status.AntivirusSignatureVersion)"
    Write-Output "AMEngineVersion           : $($status.AMEngineVersion)"
    Write-Output "AMProductVersion          : $($status.AMProductVersion)"
}

Write-Output ""
Write-Output "--- Tamper Protection Registry ---"
$tamper = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features' -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
Write-Output "TamperProtection registry value: $tamper  (5 = enabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        if "DEFENDER_UNAVAILABLE" in output:
            result.status = STATUS_WARNING
            result.finding = "Windows Defender status could not be retrieved. A third-party AV may be active — verify manually."
            result.remediation = "Confirm an enterprise EDR or AV solution is active and reporting to a central console."
            return result

        failures = []
        warnings = []

        if "RealTimeProtectionEnabled : False" in output:
            failures.append("Real-time protection is DISABLED")
        if "BehaviorMonitorEnabled    : False" in output:
            failures.append("Behavior monitoring is DISABLED")
        if "TamperProtection registry value: 5" not in output:
            warnings.append(
                "Tamper protection may not be enabled (registry value != 5)"
            )
        if (
            "CloudProtectionEnabled    : 0" in output
            or "CloudProtectionEnabled    :" not in output
        ):
            warnings.append("Cloud-delivered protection (MAPS) may not be enabled")

        # Check signature age
        for line in output.splitlines():
            if "AntivirusSignatureAge" in line:
                try:
                    age = int(line.split(":")[1].strip().split()[0])
                    if age > 3:
                        failures.append(
                            f"Signature age is {age} days — exceeds 3-day threshold"
                        )
                except (ValueError, IndexError):
                    pass

        if failures:
            result.status = STATUS_FAIL
            result.finding = "Defender issues found: " + "; ".join(failures)
            result.remediation = (
                "Address each failed item. Ensure Defender is not being disabled by policy. "
                "Enable tamper protection to prevent unauthorized configuration changes."
            )
        elif warnings:
            result.status = STATUS_WARNING
            result.finding = (
                "Defender is active but some hardening items need review: "
                + "; ".join(warnings)
            )
            result.remediation = (
                "Enable tamper protection and cloud-delivered protection for maximum coverage. "
                "Review Microsoft Defender for Endpoint if available in your licensing."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "Windows Defender is fully enabled with tamper protection and cloud protection active."

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-007 — BitLocker Encryption Status
# ---------------------------------------------------------------------------
