"""
PS-005_powershell_v2_disabled.py
--------------------------------
PowerShell v2 does not support Script Block Logging or AMSI.
Attackers invoke it specifically to bypass modern PS security controls.

Check ID : PS-005
Category : PowerShell Security
Framework: NIST CM-7, CIS 18.9.99
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


@register_check("PS-005")
def check_ps_v2_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the PowerShell v2 engine is disabled to prevent logging bypass."""
    result = base_result(
        connector,
        "PS-005",
        "PowerShell v2 Engine Disabled",
        "Verify PowerShell v2 is disabled to prevent its use as a logging bypass vector.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$v2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue)
if ($v2) {
    Write-Output "PS V2 Feature State: $($v2.State)"
} else {
    Write-Output "PS V2 Feature State: unknown"
}
$v2root = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
if ($v2root) { Write-Output "PS V2 Engine State: $($v2root.State)" }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout.lower()
        if "disabled" in output:
            result.status = STATUS_PASS
            result.finding = "PowerShell v2 engine is disabled."
            result.remediation = ""
        elif "enabled" in output:
            result.status = STATUS_FAIL
            result.finding = "PowerShell v2 engine is ENABLED and can be used to bypass Script Block Logging and AMSI."
            result.remediation = (
                "Disable via PowerShell: Disable-WindowsOptionalFeature -Online "
                "-FeatureName MicrosoftWindowsPowerShellV2Root. "
                "Or via Server Manager > Remove Features > PowerShell 2.0."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "Could not determine PowerShell v2 status. Manual verification required."
            result.remediation = "Run: Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root"
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
