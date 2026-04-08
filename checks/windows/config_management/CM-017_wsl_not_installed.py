"""
CM-017_wsl_not_installed.py
----------------------------
Windows Subsystem for Linux (WSL) should not be installed on managed servers
and workstations. WSL can be used to bypass Windows application control
policies, access Linux binaries, and complicate security monitoring.

Check ID : CM-017
Category : Configuration Management
Framework: NIST CM-7, DISA STIG CAT-II
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


@register_check("CM-017")
def check_wsl_not_installed(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows Subsystem for Linux (WSL) is not installed."""
    result = base_result(
        connector,
        "CM-017",
        "WSL Not Installed",
        "Verify the Windows Subsystem for Linux optional feature is disabled.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
if ($null -eq $feature) {
    Write-Output "WSL_STATE: NotFound"
} else {
    Write-Output "WSL_STATE: $($feature.State)"
}
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        state = "Unknown"
        for line in cmd.stdout.splitlines():
            if line.startswith("WSL_STATE:"):
                state = line.split(":", 1)[1].strip()
                break

        if state in ("Disabled", "NotFound", "Unknown"):
            result.status = STATUS_PASS
            result.finding = (
                f"Windows Subsystem for Linux is not enabled (state: {state})."
            )
            result.remediation = ""
        elif state == "Enabled":
            result.status = STATUS_FAIL
            result.finding = (
                "Windows Subsystem for Linux (WSL) is ENABLED. "
                "WSL can bypass application control policies and complicates security monitoring."
            )
            result.remediation = (
                "Disable WSL: Disable-WindowsOptionalFeature -Online -FeatureName "
                "Microsoft-Windows-Subsystem-Linux -NoRestart, or via Server Manager / DISM. "
                "Block via Group Policy if re-enablement is a concern."
            )
        else:
            result.status = STATUS_PASS
            result.finding = f"WSL feature state is '{state}' — treated as not active."
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
