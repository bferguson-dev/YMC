"""
PS-006_constrained_language_mode.py
-----------------------------------
Constrained Language Mode restricts PowerShell to a safe subset of commands,
blocking COM objects, .NET type access, and other techniques used in attacks.

Check ID : PS-006
Category : PowerShell Security
Framework: NIST CM-7, CIS 18.9.100
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


@register_check("PS-006")
def check_ps_constrained_language(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell Constrained Language Mode is active."""
    result = base_result(
        connector,
        "PS-006",
        "PowerShell Constrained Language Mode",
        "Verify PowerShell Constrained Language Mode is enforced to limit attack surface.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "LanguageMode: $($ExecutionContext.SessionState.LanguageMode)"
$applocker = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
if ($applocker) { Write-Output "AppLocker policy present: True" }
else { Write-Output "AppLocker policy present: False" }
$wdac = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -ErrorAction SilentlyContinue)
Write-Output "WDAC config key exists: $($null -ne $wdac)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        mode = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("LanguageMode:"):
                mode = line.split(":", 1)[1].strip().lower()
        if mode == "constrainedlanguage":
            result.status = STATUS_PASS
            result.finding = "PowerShell is running in Constrained Language Mode."
            result.remediation = ""
        elif mode == "fulllanguage":
            result.status = STATUS_WARNING
            result.finding = "PowerShell is running in Full Language Mode. Constrained Language Mode is not enforced."
            result.remediation = (
                "Enforce Constrained Language Mode via AppLocker or Windows Defender Application Control (WDAC). "
                "WDAC is the recommended approach on Windows 10/Server 2016+."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"PowerShell Language Mode is '{mode}'. Review whether this is appropriate."
            result.remediation = (
                "Enforce Constrained Language Mode via AppLocker or WDAC policies."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
