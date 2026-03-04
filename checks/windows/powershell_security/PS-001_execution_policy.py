"""
PS-001_execution_policy.py
--------------------------
Unrestricted or Bypass execution policy allows any script to run without restriction,
enabling malware and attacker tooling to execute freely.

Check ID : PS-001
Category : PowerShell Security
Framework: NIST CM-7, CIS 18.9.95
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


@register_check("PS-001")
def check_ps_execution_policy(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell execution policy is set to RemoteSigned or AllSigned."""
    result = base_result(
        connector,
        "PS-001",
        "PowerShell Execution Policy",
        "Verify PowerShell execution policy prevents unsigned script execution.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$machine = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue).ExecutionPolicy
$user    = (Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue).ExecutionPolicy
$gpo     = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue).ExecutionPolicy
Write-Output "Machine policy : $machine"
Write-Output "User policy    : $user"
Write-Output "GPO policy     : $gpo"
Write-Output "Effective      : $(Get-ExecutionPolicy -Scope LocalMachine)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        effective = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("Effective"):
                effective = line.split(":", 1)[1].strip().lower()
        safe = {"restricted", "allsigned", "remotesigned"}
        risky = {"unrestricted", "bypass", "undefined"}
        if effective in safe:
            result.status = STATUS_PASS
            result.finding = f"PowerShell execution policy is '{effective}' — prevents unsigned script execution."
            result.remediation = ""
        elif effective in risky:
            result.status = STATUS_FAIL
            result.finding = f"PowerShell execution policy is '{effective}' — allows unsigned and potentially malicious scripts."
            result.remediation = (
                "Set via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Windows PowerShell > 'Turn on Script Execution'. "
                "Recommended: RemoteSigned or AllSigned."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"PowerShell execution policy effective value is '{effective}' — review manually."
            result.remediation = "Confirm execution policy via 'Get-ExecutionPolicy -List' and set appropriately."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
