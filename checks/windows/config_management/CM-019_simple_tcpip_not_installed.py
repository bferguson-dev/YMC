"""
CM-019_simple_tcpip_not_installed.py
--------------------------------------
Simple TCP/IP Services (echo, discard, daytime, character generator, quote of
the day) are legacy services with no legitimate use on modern systems. They
can be abused for amplification attacks and should not be installed.

Check ID : CM-019
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


@register_check("CM-019")
def check_simple_tcpip_not_installed(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Simple TCP/IP Services is not installed."""
    result = base_result(
        connector,
        "CM-019",
        "Simple TCP/IP Services Not Installed",
        "Verify the SimpleTCP optional feature is disabled.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$feature = Get-WindowsOptionalFeature -Online -FeatureName SimpleTCP -ErrorAction SilentlyContinue
if ($null -eq $feature) {
    Write-Output "SIMPLETCP_STATE: NotFound"
} else {
    Write-Output "SIMPLETCP_STATE: $($feature.State)"
}
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        state = "Unknown"
        for line in cmd.stdout.splitlines():
            if line.startswith("SIMPLETCP_STATE:"):
                state = line.split(":", 1)[1].strip()
                break

        if state in ("Disabled", "NotFound", "Unknown"):
            result.status = STATUS_PASS
            result.finding = (
                f"Simple TCP/IP Services is not installed (state: {state})."
            )
            result.remediation = ""
        elif state == "Enabled":
            result.status = STATUS_FAIL
            result.finding = (
                "Simple TCP/IP Services (SimpleTCP) is INSTALLED. "
                "Legacy services echo/discard/daytime/chargen can be abused for amplification attacks."
            )
            result.remediation = (
                "Disable: Disable-WindowsOptionalFeature -Online -FeatureName SimpleTCP -NoRestart "
                "or via DISM: dism /online /disable-feature /featurename:SimpleTCP."
            )
        else:
            result.status = STATUS_PASS
            result.finding = (
                f"SimpleTCP feature state is '{state}' — treated as not active."
            )
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
