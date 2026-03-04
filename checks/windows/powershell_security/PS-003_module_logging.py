"""
PS-003_module_logging.py
------------------------
Module Logging records the input and output of every PowerShell pipeline execution,
providing visibility into all cmdlet calls including those from scripts.

Check ID : PS-003
Category : PowerShell Security
Framework: NIST AU-3, CIS 18.9.97
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


@register_check("PS-003")
def check_ps_module_logging(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell Module Logging is enabled."""
    result = base_result(
        connector,
        "PS-003",
        "PowerShell Module Logging",
        "Verify PowerShell module logging is enabled to capture pipeline execution details.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$ml = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging
Write-Output "EnableModuleLogging: $ml  (1=enabled)"
$modules = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames' -ErrorAction SilentlyContinue)
Write-Output "Module scope: $($modules.'*')"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        ml = None
        for line in cmd.stdout.splitlines():
            if line.startswith("EnableModuleLogging:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    ml = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if ml == 1:
            result.status = STATUS_PASS
            result.finding = "PowerShell Module Logging is enabled."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = f"PowerShell Module Logging is NOT enabled (value: {ml})."
            result.remediation = (
                "Enable via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Windows PowerShell > 'Turn on Module Logging'. "
                "Set module names to '*' to capture all modules."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
