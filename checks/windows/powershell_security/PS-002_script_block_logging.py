"""
PS-002_script_block_logging.py
------------------------------
Script Block Logging records the full content of every PowerShell script block executed,
enabling detection of obfuscated or malicious PowerShell activity.

Check ID : PS-002
Category : PowerShell Security
Framework: NIST AU-3, CIS 18.9.96
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


@register_check("PS-002")
def check_ps_script_block_logging(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell Script Block Logging is enabled."""
    result = base_result(
        connector,
        "PS-002",
        "PowerShell Script Block Logging",
        "Verify PowerShell script block logging is enabled to capture all executed PS code.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$sbl = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$inv = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging
Write-Output "EnableScriptBlockLogging          : $sbl  (1=enabled)"
Write-Output "EnableScriptBlockInvocationLogging: $inv  (1=enabled)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        sbl = None
        for line in cmd.stdout.splitlines():
            if "EnableScriptBlockLogging" in line and "Invocation" not in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    sbl = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if sbl == 1:
            result.status = STATUS_PASS
            result.finding = "PowerShell Script Block Logging is enabled."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"PowerShell Script Block Logging is NOT enabled (value: {sbl})."
            )
            result.remediation = (
                "Enable via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Windows PowerShell > 'Turn on PowerShell Script Block Logging'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
