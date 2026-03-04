"""
AU-010_windows_error_reporting.py
---------------------------------
Windows Error Reporting can transmit memory dump fragments and application data
to Microsoft servers. In high-security environments this should be disabled.

Check ID : AU-010
Category : Audit & Logging
Framework: NIST AU-13, CIS 18.9.18
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


@register_check("AU-010")
def check_windows_error_reporting(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows Error Reporting is configured or disabled appropriately."""
    result = base_result(
        connector,
        "AU-010",
        "Windows Error Reporting Configuration",
        "Verify Windows Error Reporting does not transmit sensitive crash data externally.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$wer = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting' -ErrorAction SilentlyContinue
Write-Output "Disabled             : $($wer.Disabled)  (1=disabled)"
Write-Output "DontSendAdditionalData: $($wer.DontSendAdditionalData)  (1=no extra data)"
$policy = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting' -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
Write-Output "Policy Disabled      : $policy  (1=disabled via GPO)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        disabled = None
        policy_disabled = None
        for line in cmd.stdout.splitlines():
            if line.startswith("Disabled             :"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    disabled = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
            if line.startswith("Policy Disabled      :"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    policy_disabled = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if disabled == 1 or policy_disabled == 1:
            result.status = STATUS_PASS
            result.finding = "Windows Error Reporting is disabled."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Windows Error Reporting is enabled (Disabled={disabled}). Crash data may be transmitted externally."
            result.remediation = (
                "For high-security environments, disable via GPO: Computer Configuration > "
                "Administrative Templates > Windows Components > Windows Error Reporting > "
                "'Disable Windows Error Reporting'. "
                "Or set HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting Disabled=1."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
