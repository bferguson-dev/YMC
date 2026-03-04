"""
AC-015_blank_passwords.py
-------------------------
Windows can be configured to prevent blank-password accounts from authenticating
over the network. This check verifies that protection is in place.

Check ID : AC-015
Category : Credential & Authentication
Framework: NIST IA-5, PCI DSS 8.3.1, CIS 1.4
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


@register_check("AC-015")
def check_blank_passwords(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Checks whether local accounts with blank passwords can authenticate over the network."""
    result = base_result(
        connector,
        "AC-015",
        "Accounts with Blank Passwords",
        "Verify the system prevents network authentication with blank passwords.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$val = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LimitBlankPasswordUse' -ErrorAction SilentlyContinue).LimitBlankPasswordUse
Write-Output "LimitBlankPasswordUse: $val  (1 = network auth blocked for blank passwords)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = ""
        for line in cmd.stdout.splitlines():
            if "LimitBlankPasswordUse:" in line:
                val = line.split(":", 1)[1].strip().split()[0]
        if val == "1":
            result.status = STATUS_PASS
            result.finding = "Network authentication with blank passwords is blocked (LimitBlankPasswordUse=1)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"Blank password network authentication restriction is NOT enabled (value: {val or 'not set'})."
            result.remediation = (
                "Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa LimitBlankPasswordUse=1. "
                "GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Accounts: Limit local account use of blank passwords to console logon only'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
