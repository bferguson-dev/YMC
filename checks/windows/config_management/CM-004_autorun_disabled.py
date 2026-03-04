"""
CM-004_autorun_disabled.py
--------------------------
Verifies AutoRun and AutoPlay are disabled via registry and Group Policy.

Check ID : CM-004
Category : Config Management
Framework: NIST CM-7, CIS 8.5

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern — no other files need to be modified.
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


@register_check("CM-004")
def check_autorun_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies AutoRun and AutoPlay are disabled via registry and Group Policy."""
    result = base_result(
        connector,
        "CM-004",
        "AutoRun and AutoPlay Disabled",
        "Verify AutoRun and AutoPlay are disabled to prevent malware auto-execution from removable media.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- AutoRun / AutoPlay Settings ---"

# NoDriveTypeAutoRun = 255 (0xFF) disables autorun for all drive types
$autoRunKey  = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'
$autoRunGPO  = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'

foreach ($path in @($autoRunKey, $autoRunGPO)) {
    if (Test-Path $path) {
        $val = (Get-ItemProperty $path -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        Write-Output "Path: $path"
        Write-Output "  NoDriveTypeAutoRun: $val (255 = fully disabled)"
    }
}

# Check AutoPlay policy
$autoPlayPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer'
if (Test-Path $autoPlayPath) {
    $noAutoPlay = (Get-ItemProperty $autoPlayPath -Name 'NoAutoplayfornonVolume' -ErrorAction SilentlyContinue).NoAutoplayfornonVolume
    Write-Output "NoAutoplayfornonVolume: $noAutoPlay"
}

# Check via CIM
$autoRunPolicy = Get-CimInstance -Namespace 'root\\rsop\\computer' `
    -ClassName 'RSOP_PolicySetting' -ErrorAction SilentlyContinue |
    Where-Object { $_.SettingName -like '*autorun*' -or $_.SettingName -like '*autoplay*' }

if ((Get-ItemProperty $autoRunKey -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun -eq 255) {
    Write-Output "AUTORUN_STATUS: PASS"
} else {
    Write-Output "AUTORUN_STATUS: FAIL - AutoRun is not fully disabled"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "AUTORUN_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "AutoRun is disabled for all drive types."
        elif "AUTORUN_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "AutoRun is not fully disabled — risk of malware auto-execution from removable media."
            result.remediation = (
                "Set NoDriveTypeAutoRun = 255 (0xFF) via GPO:\n"
                "Computer Configuration > Administrative Templates > Windows Components > "
                "AutoPlay Policies > 'Turn off AutoPlay' = Enabled, All Drives."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "AutoRun status could not be definitively determined. Review raw evidence."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-005 — Windows Firewall Enabled (All Profiles)
# ---------------------------------------------------------------------------
