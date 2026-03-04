"""
AC-014_password_not_required.py
-------------------------------
The PASSWD_NOTREQD flag allows accounts to authenticate with a blank password,
creating a trivial authentication bypass.

Check ID : AC-014
Category : Credential & Authentication
Framework: NIST IA-5, PCI DSS 8.3.1, CIS 1.3
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


@register_check("AC-014")
def check_password_not_required(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Identifies enabled local accounts with the PASSWD_NOTREQD flag set."""
    result = base_result(
        connector,
        "AC-014",
        "Password Not Required Flag",
        "Identify enabled local accounts where a password is not required to authenticate.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$accounts = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.PasswordRequired -eq $false -and
    $_.Name -notin @('DefaultAccount','WDAGUtilityAccount','Guest')
}
if ($accounts.Count -eq 0) {
    Write-Output "COMPLIANT: No enabled accounts have password-not-required flag set."
} else {
    Write-Output "NON-COMPLIANT: $($accounts.Count) account(s) do not require a password:"
    $accounts | ForEach-Object { Write-Output "  - $($_.Name) | Enabled: $($_.Enabled)" }
}
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        if "COMPLIANT:" in cmd.stdout and "NON-COMPLIANT" not in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "All enabled local accounts require a password."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "One or more enabled accounts do not require a password. See raw evidence."
            result.remediation = (
                "Use Set-LocalUser -Name <name> -PasswordRequired $true "
                "or via Local Security Policy to require passwords for all accounts."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
