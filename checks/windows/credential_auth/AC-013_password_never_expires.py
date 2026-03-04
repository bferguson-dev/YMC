"""
AC-013_password_never_expires.py
--------------------------------
Non-expiring passwords mean compromised credentials remain valid indefinitely.
Service account exceptions must be documented.

Check ID : AC-013
Category : Credential & Authentication
Framework: NIST IA-5, PCI DSS 8.3.9, CIS 1.2
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


@register_check("AC-013")
def check_password_never_expires(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Identifies enabled local accounts with passwords set to never expire."""
    result = base_result(
        connector,
        "AC-013",
        "Password Never Expires Accounts",
        "Identify enabled local accounts with non-expiring passwords.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$accounts = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.PasswordNeverExpires -eq $true -and
    $_.Name -notin @('DefaultAccount','WDAGUtilityAccount')
}
if ($accounts.Count -eq 0) {
    Write-Output "COMPLIANT: No enabled accounts have password set to never expire."
} else {
    Write-Output "NON-COMPLIANT: $($accounts.Count) account(s):"
    $accounts | ForEach-Object { Write-Output "  - $($_.Name) | LastPasswordSet: $($_.PasswordLastSet)" }
}
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        if "COMPLIANT:" in cmd.stdout and "NON-COMPLIANT" not in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "No enabled local accounts have passwords set to never expire."
            )
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "One or more enabled accounts have passwords set to never expire. See raw evidence."
            result.remediation = (
                "Enable password expiration for standard users. "
                "For service accounts, document exceptions and store credentials in a PAM solution."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
