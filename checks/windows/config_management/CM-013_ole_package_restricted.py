"""
CM-013_ole_package_restricted.py
---------------------------------
Verifies OLE package activation is restricted.

Check ID : CM-013
Category : Configuration Management
Framework: NIST CM-7, CIS 18.9.2
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


@register_check("CM-013")
def check_ole_package_restricted(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies OLE object package activation is restricted to prevent embedded malware execution."""
    result = base_result(
        connector,
        "CM-013",
        "OLE Package Activation Restricted",
        "Verify OLE package activation is restricted to prevent malware execution via embedded objects.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$pkg = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableSecureUIAPaths' -ErrorAction SilentlyContinue).EnableSecureUIAPaths
Write-Output "EnableSecureUIAPaths: $pkg"
$ole = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Ole' -Name 'DefaultLaunchPermission' -ErrorAction SilentlyContinue)
Write-Output "OLE DefaultLaunchPermission present: $($null -ne $ole)"
$packager = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations' -Name 'LowRiskFileTypes' -ErrorAction SilentlyContinue).LowRiskFileTypes
Write-Output "LowRiskFileTypes: $packager"
$cfgExe = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Packager' -Name 'DisableActivationPrompt' -ErrorAction SilentlyContinue).DisableActivationPrompt
Write-Output "OLE Packager DisableActivationPrompt: $cfgExe  (0=prompts shown/safer)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        disable_prompt = None
        for line in cmd.stdout.splitlines():
            if "OLE Packager DisableActivationPrompt:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    disable_prompt = int(v)
                except ValueError:
                    pass

        if disable_prompt == 1:
            result.status = STATUS_FAIL
            result.finding = "OLE Package activation prompts are disabled (DisableActivationPrompt=1). Embedded objects activate without warning."
            result.remediation = (
                "Set HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Packager "
                "DisableActivationPrompt=0 or remove the key to restore prompts."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "OLE Package activation prompts are not suppressed. Users are warned before embedded objects activate."
            result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
