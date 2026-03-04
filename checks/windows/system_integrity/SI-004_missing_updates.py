"""
SI-004_missing_updates.py
-------------------------
Queries Windows Update for pending/missing updates using the

Check ID : SI-004
Category : System Integrity
Framework: NIST SI-2

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


@register_check("SI-004")
def check_missing_updates(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Queries Windows Update for pending/missing updates using the
    Microsoft.Update.Session COM object. Returns count and titles of
    missing updates, flagging critical and security updates specifically.
    Note: This check may take 30-60 seconds to complete.
    """
    result = base_result(
        connector,
        "SI-004",
        "Missing Windows Updates",
        "Enumerate pending Windows updates, flagging security and critical updates.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Missing Windows Updates ---"
Write-Output "Querying Windows Update (this may take 30-60 seconds)..."

try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and Type='Software'")
    $updates = $result.Updates

    if ($updates.Count -eq 0) {
        Write-Output "COMPLIANT: No missing updates found."
    } else {
        $critical = $updates | Where-Object { $_.MsrcSeverity -eq 'Critical' }
        $important = $updates | Where-Object { $_.MsrcSeverity -eq 'Important' }
        $other = $updates | Where-Object { $_.MsrcSeverity -notin @('Critical', 'Important') }

        Write-Output "NON-COMPLIANT: $($updates.Count) missing update(s) found."
        Write-Output "  Critical  : $($critical.Count)"
        Write-Output "  Important : $($important.Count)"
        Write-Output "  Other     : $($other.Count)"
        Write-Output ""
        Write-Output "--- Critical Updates ---"
        $critical | ForEach-Object { Write-Output "  [CRITICAL] $($_.Title)" }
        Write-Output "--- Important Updates ---"
        $important | Select-Object -First 10 | ForEach-Object { Write-Output "  [IMPORTANT] $($_.Title)" }
        if ($important.Count -gt 10) { Write-Output "  ... and $($important.Count - 10) more important updates" }
    }
} catch {
    Write-Output "UPDATE_CHECK_ERROR: $($_.Exception.Message)"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        if "COMPLIANT: No missing updates" in output:
            result.status = STATUS_PASS
            result.finding = "No missing Windows updates detected."
        elif "UPDATE_CHECK_ERROR" in output:
            result.status = STATUS_WARNING
            result.finding = "Windows Update query failed — WSUS or update service may be unavailable. Review raw evidence."
            result.remediation = "Verify Windows Update service is running and WSUS connectivity if applicable."
        elif "NON-COMPLIANT" in output:
            # Extract counts
            critical_count = 0
            important_count = 0
            for line in output.splitlines():
                if "Critical  :" in line:
                    try:
                        critical_count = int(line.split(":")[1].strip())
                    except ValueError:
                        pass
                if "Important :" in line:
                    try:
                        important_count = int(line.split(":")[1].strip())
                    except ValueError:
                        pass

            result.status = STATUS_FAIL if critical_count > 0 else STATUS_WARNING
            result.finding = (
                f"Missing updates detected: {critical_count} Critical, "
                f"{important_count} Important. See raw evidence for titles."
            )
            result.remediation = (
                "Apply all Critical and Important updates immediately. "
                "Critical security updates should be applied within 72 hours per most frameworks. "
                "Use WSUS, SCCM, or Windows Update for Business for centralized patch management."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Update check output was unexpected. Review raw evidence manually."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CIS-001 — CIS Microsoft Windows Benchmark Subset
# ---------------------------------------------------------------------------
