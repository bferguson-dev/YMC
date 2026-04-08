"""
SV-008_remote_assistance_disabled.py
--------------------------------------
Remote Assistance allows a helper to connect to the system at a user's
invitation. On managed servers, this creates an uncontrolled remote access
vector and should be disabled via registry policy.

Check ID : SV-008
Category : Services
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


@register_check("SV-008")
def check_remote_assistance_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Remote Assistance is disabled via fAllowToGetHelp registry key."""
    result = base_result(
        connector,
        "SV-008",
        "Remote Assistance Disabled",
        "Verify Remote Assistance (fAllowToGetHelp) is disabled.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = r"""
$val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -ErrorAction SilentlyContinue).fAllowToGetHelp
Write-Output "fAllowToGetHelp: $val  (0=disabled/safe, 1=enabled/unsafe)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        val = None
        for line in cmd.stdout.splitlines():
            if line.startswith("fAllowToGetHelp:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    val = int(v)
                except (TypeError, ValueError):
                    pass

        if val == 0:
            result.status = STATUS_PASS
            result.finding = "Remote Assistance is disabled (fAllowToGetHelp=0)."
            result.remediation = ""
        elif val == 1:
            result.status = STATUS_FAIL
            result.finding = (
                "Remote Assistance is ENABLED (fAllowToGetHelp=1). "
                "This creates an uncontrolled remote access channel on managed systems."
            )
            result.remediation = (
                "Disable Remote Assistance via Group Policy: "
                "Computer Configuration > Administrative Templates > System > Remote Assistance > "
                "Configure Offer Remote Assistance = Disabled. "
                "Or set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance "
                "fAllowToGetHelp=0 (DWORD)."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "fAllowToGetHelp registry key is not set. "
                "Windows default may allow Remote Assistance — explicit disable is required."
            )
            result.remediation = (
                "Explicitly disable Remote Assistance: set fAllowToGetHelp=0 or configure "
                "via Group Policy (Computer Configuration > System > Remote Assistance)."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
