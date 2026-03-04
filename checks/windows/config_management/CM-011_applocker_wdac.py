"""
CM-011_applocker_wdac.py
------------------------
Verifies AppLocker or Windows Defender Application Control policy is present.

Check ID : CM-011
Category : Configuration Management
Framework: NIST CM-7, CIS 2.5
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("CM-011")
def check_applocker_wdac(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies AppLocker or WDAC application control policy is configured."""
    result = base_result(
        connector,
        "CM-011",
        "Application Control Policy (AppLocker/WDAC)",
        "Verify an application whitelist policy is in place via AppLocker or WDAC.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- AppLocker ---"
try {
    $al = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    if ($al) {
        $ruleCount = ($al.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        Write-Output "AppLocker effective policy: present"
        Write-Output "AppLocker rule count: $ruleCount"
        $al.RuleCollections | ForEach-Object { Write-Output "  Collection: $($_.RuleCollectionType) ($($_.Count) rules)" }
    } else { Write-Output "AppLocker effective policy: none" }
} catch { Write-Output "AppLocker effective policy: unavailable - $_" }

Write-Output ""
Write-Output "--- WDAC ---"
$wdac = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -ErrorAction SilentlyContinue)
Write-Output "WDAC CI config key: $(if($wdac){'present'}else{'not present'})"
$wdacPolicy = Get-Item 'C:\\Windows\\System32\\CodeIntegrity\\SIPolicy.p7b' -ErrorAction SilentlyContinue
Write-Output "WDAC SIPolicy.p7b: $(if($wdacPolicy){'present'}else{'not present'})"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        al_present = "AppLocker effective policy: present" in output
        al_rules = 0
        wdac_present = (
            "WDAC CI config key: present" in output
            or "WDAC SIPolicy.p7b: present" in output
        )
        for line in output.splitlines():
            if "AppLocker rule count:" in line:
                try:
                    al_rules = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        if (al_present and al_rules > 0) or wdac_present:
            result.status = STATUS_PASS
            result.finding = (
                f"Application control policy is in place — "
                f"AppLocker: {'yes (' + str(al_rules) + ' rules)' if al_present else 'no'}, "
                f"WDAC: {'yes' if wdac_present else 'no'}."
            )
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = "No AppLocker or WDAC application control policy found. Any executable can run."
            result.remediation = (
                "Implement application control. WDAC is preferred on Windows 10/Server 2016+. "
                "Start with audit mode before enforcing. "
                "AppLocker: Computer Configuration > Windows Settings > Security Settings > Application Control Policies."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
