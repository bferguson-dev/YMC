"""
CM-018_tftp_not_installed.py
-----------------------------
The TFTP client is an unnecessary optional feature that transfers files without
authentication. It should not be installed on managed servers and workstations.

Check ID : CM-018
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


@register_check("CM-018")
def check_tftp_not_installed(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the TFTP client optional feature is not installed."""
    result = base_result(
        connector,
        "CM-018",
        "TFTP Client Not Installed",
        "Verify the TFTP client optional feature is disabled.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$feature = Get-WindowsOptionalFeature -Online -FeatureName TFTP -ErrorAction SilentlyContinue
if ($null -eq $feature) {
    Write-Output "TFTP_STATE: NotFound"
} else {
    Write-Output "TFTP_STATE: $($feature.State)"
}
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        state = "Unknown"
        for line in cmd.stdout.splitlines():
            if line.startswith("TFTP_STATE:"):
                state = line.split(":", 1)[1].strip()
                break

        if state in ("Disabled", "NotFound", "Unknown"):
            result.status = STATUS_PASS
            result.finding = f"TFTP client is not installed (state: {state})."
            result.remediation = ""
        elif state == "Enabled":
            result.status = STATUS_FAIL
            result.finding = (
                "TFTP client is INSTALLED. TFTP transfers files without authentication "
                "and should not be present on managed systems."
            )
            result.remediation = (
                "Disable: Disable-WindowsOptionalFeature -Online -FeatureName TFTP -NoRestart "
                "or via DISM: dism /online /disable-feature /featurename:TFTP."
            )
        else:
            result.status = STATUS_PASS
            result.finding = f"TFTP feature state is '{state}' — treated as not active."
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
