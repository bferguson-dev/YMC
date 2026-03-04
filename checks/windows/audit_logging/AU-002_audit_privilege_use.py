"""
AU-002_audit_privilege_use.py
-----------------------------
Verifies that privilege use events are audited.

Check ID : AU-002
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


@register_check("AU-002")
def check_audit_privilege_use(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies that privilege use events are audited."""
    result = base_result(
        connector,
        "AU-002",
        "Audit Policy: Privilege Use",
        "Verify that privilege use (sensitive and non-sensitive) is audited.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Audit Policy: Privilege Use ---"
$sensitive    = auditpol /get /subcategory:"Sensitive Privilege Use"     /r | ConvertFrom-Csv
$nonSensitive = auditpol /get /subcategory:"Non Sensitive Privilege Use" /r | ConvertFrom-Csv
Write-Output "Sensitive Privilege Use     : $($sensitive.'Inclusion Setting')"
Write-Output "Non-Sensitive Privilege Use : $($nonSensitive.'Inclusion Setting')"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        output = cmd.stdout
        if "Success and Failure" in output or "Success" in output:
            result.status = STATUS_PASS
            result.finding = "Privilege use events are being audited."
        else:
            result.status = STATUS_FAIL
            result.finding = "Privilege use auditing is not enabled."
            result.remediation = (
                'Enable via: auditpol /set /subcategory:"Sensitive Privilege Use" '
                "/success:enable /failure:enable"
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-003 — Audit Policy: Account Management
# ---------------------------------------------------------------------------
