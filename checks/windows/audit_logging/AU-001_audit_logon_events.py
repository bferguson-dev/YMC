"""
AU-001_audit_logon_events.py
----------------------------
Verifies that logon/logoff events are audited (success and failure).

Check ID : AU-001
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
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AU-001")
def check_audit_logon_events(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies that logon/logoff events are audited (success and failure)."""
    result = base_result(
        connector,
        "AU-001",
        "Audit Policy: Logon Events",
        "Verify that logon and logoff events are audited for both success and failure.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Audit Policy: Logon/Logoff ---"
$logon  = auditpol /get /subcategory:"Logon"  /r | ConvertFrom-Csv
$logoff = auditpol /get /subcategory:"Logoff" /r | ConvertFrom-Csv
$failedLogon = auditpol /get /subcategory:"Account Lockout" /r | ConvertFrom-Csv
Write-Output "Logon Audit Setting       : $($logon.'Inclusion Setting')"
Write-Output "Logoff Audit Setting      : $($logoff.'Inclusion Setting')"
Write-Output "Account Lockout Setting   : $($failedLogon.'Inclusion Setting')"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        output = cmd.stdout
        if "Success and Failure" in output or (
            "Success" in output and "Failure" in output
        ):
            result.status = STATUS_PASS
            result.finding = "Logon/logoff events are audited for success and failure."
        elif "Success" in output:
            result.status = STATUS_FAIL
            result.finding = "Logon events audited for Success only — Failure events are not captured."
            result.remediation = (
                'Run: auditpol /set /subcategory:"Logon" /success:enable /failure:enable\n'
                "Or configure via GPO: Computer Configuration > Windows Settings > "
                "Security Settings > Advanced Audit Policy Configuration."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "Logon event auditing is not configured or is set to No Auditing."
            )
            result.remediation = (
                "Enable logon auditing via Group Policy or auditpol command. "
                "Both Success and Failure must be enabled."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-002 — Audit Policy: Privilege Use
# ---------------------------------------------------------------------------
