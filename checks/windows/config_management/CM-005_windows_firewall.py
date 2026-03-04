"""
CM-005_windows_firewall.py
--------------------------
Verifies Windows Firewall is enabled on all three profiles (Domain, Private, Public).

Check ID : CM-005
Category : Config Management
Framework: NIST SC-7

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


@register_check("CM-005")
def check_windows_firewall(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows Firewall is enabled on all three profiles (Domain, Private, Public)."""
    result = base_result(
        connector,
        "CM-005",
        "Windows Firewall Enabled (All Profiles)",
        "Verify Windows Firewall is enabled for Domain, Private, and Public profiles.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Windows Firewall Status ---"
$profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
$profiles | ForEach-Object {
    Write-Output "Profile: $($_.Name)"
    Write-Output "  Enabled              : $($_.Enabled)"
    Write-Output "  Default Inbound      : $($_.DefaultInboundAction)"
    Write-Output "  Default Outbound     : $($_.DefaultOutboundAction)"
}
$disabled = $profiles | Where-Object { $_.Enabled -eq $false }
if ($disabled.Count -eq 0) {
    Write-Output "FIREWALL_STATUS: PASS - All firewall profiles are enabled."
} else {
    $names = $disabled.Name -join ', '
    Write-Output "FIREWALL_STATUS: FAIL - Firewall disabled on profile(s): $names"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "FIREWALL_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "Windows Firewall is enabled on all profiles (Domain, Private, Public)."
            )
        elif "FIREWALL_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "Windows Firewall is disabled on one or more profiles."
            result.remediation = (
                "Enable Windows Firewall on all profiles via GPO:\n"
                "Computer Configuration > Windows Settings > Security Settings > "
                "Windows Defender Firewall with Advanced Security.\n"
                "Or via PowerShell: Set-NetFirewallProfile -All -Enabled True"
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Firewall status could not be determined. Review raw evidence."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-006 — Automatic Updates Configured
# ---------------------------------------------------------------------------
