"""
CM-016_autoplay_all_drives.py
------------------------------
Verifies AutoPlay is disabled for all drive types including network and removable.

Check ID : CM-016
Category : Configuration Management
Framework: NIST CM-7, CIS 18.9.8
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


@register_check("CM-016")
def check_autoplay_all_drives(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies AutoPlay is disabled for all drive types to prevent malware auto-execution."""
    result = base_result(
        connector,
        "CM-016",
        "AutoPlay Disabled (All Drive Types)",
        "Verify AutoPlay is disabled for all drive types including removable and network drives.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$machine = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
$user    = (Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
$policy  = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
Write-Output "NoDriveTypeAutoRun (Machine): $machine  (0xFF=255=all disabled)"
Write-Output "NoDriveTypeAutoRun (User)   : $user"
Write-Output "NoDriveTypeAutoRun (Policy) : $policy"
$autoPlayDef = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers' -Name 'DisableAutoplay' -ErrorAction SilentlyContinue).DisableAutoplay
Write-Output "DisableAutoplay (global): $autoPlayDef  (1=disabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        machine_val = None
        policy_val = None
        global_disabled = None
        for line in cmd.stdout.splitlines():
            if "NoDriveTypeAutoRun (Machine):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    machine_val = int(v)
                except ValueError:
                    pass
            if "NoDriveTypeAutoRun (Policy) :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    policy_val = int(v)
                except ValueError:
                    pass
            if "DisableAutoplay (global):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    global_disabled = int(v)
                except ValueError:
                    pass

        all_disabled = machine_val == 255 or policy_val == 255 or global_disabled == 1

        if all_disabled:
            result.status = STATUS_PASS
            result.finding = "AutoPlay is disabled for all drive types (NoDriveTypeAutoRun=255 or DisableAutoplay=1)."
            result.remediation = ""
        elif machine_val is not None and machine_val > 0:
            result.status = STATUS_WARNING
            result.finding = f"AutoPlay is partially restricted (NoDriveTypeAutoRun={machine_val}) but not fully disabled for all drive types (expected 255)."
            result.remediation = (
                "Set NoDriveTypeAutoRun=255 (0xFF) to disable AutoPlay for all drive types. "
                "GPO: Computer Configuration > Administrative Templates > Windows Components > "
                "AutoPlay Policies > 'Turn off AutoPlay'. Set to All Drives."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = f"AutoPlay is not fully disabled (machine={machine_val}, policy={policy_val}). Removable and network drives can auto-execute."
            result.remediation = (
                "Disable all AutoPlay: Set "
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer "
                "NoDriveTypeAutoRun=255 (DWORD)."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
