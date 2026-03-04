"""
CM-010_windows_script_host.py
------------------------------
Verifies Windows Script Host is disabled.

Check ID : CM-010
Category : Configuration Management
Framework: NIST CM-7, CIS 18.9.1
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


@register_check("CM-010")
def check_windows_script_host(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows Script Host is disabled to prevent VBScript/JScript execution."""
    result = base_result(
        connector,
        "CM-010",
        "Windows Script Host Disabled",
        "Verify Windows Script Host is disabled to block VBScript and JScript malware execution.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$machine = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
$user    = (Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings' -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
Write-Output "WSH Enabled (Machine): $machine  (0=disabled)"
Write-Output "WSH Enabled (User)   : $user  (0=disabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        machine_val = None
        user_val = None
        for line in cmd.stdout.splitlines():
            if "WSH Enabled (Machine):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    machine_val = int(v)
                except ValueError:
                    pass
            if "WSH Enabled (User)   :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    user_val = int(v)
                except ValueError:
                    pass

        if machine_val == 0:
            result.status = STATUS_PASS
            result.finding = (
                "Windows Script Host is disabled at the machine level (Enabled=0)."
            )
            result.remediation = ""
        elif machine_val is None and user_val is None:
            result.status = STATUS_WARNING
            result.finding = "WSH Enabled registry key not set — WSH is active by default. Consider disabling if scripts are not required."
            result.remediation = (
                "Disable: Set HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings Enabled=0 (DWORD). "
                "This prevents .vbs, .vbe, .js, .jse files from executing via wscript/cscript."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = f"Windows Script Host is enabled (machine={machine_val}, user={user_val}). VBScript and JScript malware can execute."
            result.remediation = (
                "Disable: Set HKLM:\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings Enabled=0 (DWORD). "
                "Test application compatibility before deploying broadly."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
