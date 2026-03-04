"""
AC-001_inactive_accounts.py
---------------------------
Finds local user accounts that have not logged in for more than

Check ID : AC-001, AC-002
Category : Access Control
Framework: NIST AC-2, PCI DSS 8.1

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


@register_check("AC-001", "AC-002", dedup_group="inactive_accounts")
def check_inactive_accounts(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Finds local user accounts that have not logged in for more than
    the configured threshold (default 90 days) and are still enabled.
    """
    result = base_result(
        connector,
        "AC-001",
        "Inactive Accounts (>90 Days)",
        "Identify enabled local accounts with no logon activity beyond the threshold.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )
    threshold = settings.get("inactive_account_threshold_days", 90)

    ps_script = f"""
$threshold = (Get-Date).AddDays(-{threshold})
$inactive = Get-LocalUser | Where-Object {{
    $_.Enabled -eq $true -and
    $_.LastLogon -ne $null -and
    $_.LastLogon -lt $threshold -and
    $_.Name -notin @('Administrator', 'DefaultAccount', 'WDAGUtilityAccount')
}}
$neverLogged = Get-LocalUser | Where-Object {{
    $_.Enabled -eq $true -and
    $_.LastLogon -eq $null -and
    $_.Name -notin @('Administrator', 'DefaultAccount', 'WDAGUtilityAccount')
}}
$all = @($inactive) + @($neverLogged)
if ($all.Count -eq 0) {{
    Write-Output "COMPLIANT: No inactive accounts found beyond {threshold} days."
}} else {{
    Write-Output "NON-COMPLIANT: $($all.Count) inactive account(s) found:"
    $all | ForEach-Object {{
        $lastLogon = if ($_.LastLogon) {{ $_.LastLogon.ToString('yyyy-MM-dd') }} else {{ 'Never' }}
        Write-Output "  - $($_.Name) | Last Logon: $lastLogon | Enabled: $($_.Enabled)"
    }}
}}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if cmd.failed and not cmd.stdout:
            result.status = STATUS_ERROR
            result.finding = f"PowerShell error: {cmd.stderr}"
            result.remediation = (
                "Verify the account has rights to enumerate local users."
            )
        elif "COMPLIANT" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = f"No enabled accounts found with no logon activity beyond {threshold} days."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"Enabled accounts found with no activity in {threshold}+ days. See raw evidence."
            result.remediation = (
                "Disable or remove accounts that no longer require access. "
                "Review with the account owner before disabling."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Check WinRM connectivity and account permissions."

    return result


# ---------------------------------------------------------------------------
# AC-003 — Guest Account Disabled
# ---------------------------------------------------------------------------
