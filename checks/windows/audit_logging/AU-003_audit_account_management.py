"""
AU-003_audit_account_management.py
----------------------------------
Verifies that account management events are audited.

Check ID : AU-003
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


@register_check("AU-003")
def check_audit_account_management(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies that account management events are audited."""
    result = base_result(
        connector,
        "AU-003",
        "Audit Policy: Account Management",
        "Verify that user account management events are audited.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Audit Policy: Account Management ---"
$userAcct  = auditpol /get /subcategory:"User Account Management"  /r | ConvertFrom-Csv
$groupAcct = auditpol /get /subcategory:"Security Group Management" /r | ConvertFrom-Csv
Write-Output "User Account Management    : $($userAcct.'Inclusion Setting')"
Write-Output "Security Group Management  : $($groupAcct.'Inclusion Setting')"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        output = cmd.stdout
        if "Success and Failure" in output or "Success" in output:
            result.status = STATUS_PASS
            result.finding = "Account management events are being audited."
        else:
            result.status = STATUS_FAIL
            result.finding = "Account management auditing is not enabled."
            result.remediation = (
                'Enable via: auditpol /set /subcategory:"User Account Management" '
                "/success:enable /failure:enable"
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-004 — Security Event Log Minimum Size
# ---------------------------------------------------------------------------
