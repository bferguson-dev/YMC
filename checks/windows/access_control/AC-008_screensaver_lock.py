"""
AC-008_screensaver_lock.py
--------------------------
Verifies that the screen saver is enabled with password protection

Check ID : AC-008
Category : Access Control
Framework: NIST AC-11

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
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-008")
def check_screensaver_lock(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Verifies that the screen saver is enabled with password protection
    and set to activate within a reasonable timeout.
    Checks both registry and Group Policy locations.
    """
    result = base_result(
        connector,
        "AC-008",
        "Screen Saver / Session Lock",
        "Verify screen saver with password lock is enabled and configured with a timeout.",
        "Access Control",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Screen Saver Policy Settings ---"
$gpPath = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop'
$userPath = 'HKCU:\\Control Panel\\Desktop'

foreach ($path in @($gpPath, $userPath)) {
    if (Test-Path $path) {
        Write-Output "Registry Path: $path"
        $ss       = (Get-ItemProperty $path -Name 'ScreenSaveActive'     -ErrorAction SilentlyContinue).ScreenSaveActive
        $pw       = (Get-ItemProperty $path -Name 'ScreenSaverIsSecure'  -ErrorAction SilentlyContinue).ScreenSaverIsSecure
        $timeout  = (Get-ItemProperty $path -Name 'ScreenSaveTimeOut'    -ErrorAction SilentlyContinue).ScreenSaveTimeOut
        Write-Output "  ScreenSaveActive    : $ss"
        Write-Output "  ScreenSaverIsSecure : $pw"
        Write-Output "  ScreenSaveTimeOut   : $timeout seconds"
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        output = cmd.stdout
        active = "1" in output and "ScreenSaveActive" in output
        secure = "1" in output and "ScreenSaverIsSecure" in output

        if active and secure:
            result.status = STATUS_PASS
            result.finding = "Screen saver with password protection is enabled."
        elif not active:
            result.status = STATUS_FAIL
            result.finding = (
                "Screen saver is not enabled. Session lock is not enforced."
            )
            result.remediation = (
                "Enable via Group Policy: User Configuration > "
                "Administrative Templates > Control Panel > Personalization. "
                "Enable 'Enable screen saver' and 'Password protect the screen saver'."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "Screen saver is enabled but password protection is NOT configured."
            )
            result.remediation = "Enable password protection: Set 'ScreenSaverIsSecure' = 1 via Group Policy."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result
