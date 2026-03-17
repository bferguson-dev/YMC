"""
SI-007_powershell_version.py
-----------------------------
Verifies the PowerShell version is current and PS 2.0 is not the primary version.

Check ID : SI-007
Category : System Integrity
Framework: NIST CM-6, CIS 18.9.99
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


@register_check("SI-007")
def check_powershell_version(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell version is 5.1+ and PS 2.0 is not the active version."""
    result = base_result(
        connector,
        "SI-007",
        "PowerShell Version",
        "Verify PowerShell 5.1 or later is installed and PS 2.0 is not the active version.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "PSVersion: $($PSVersionTable.PSVersion)"
Write-Output "PSEdition: $($PSVersionTable.PSEdition)"
Write-Output "CLRVersion: $($PSVersionTable.CLRVersion)"
$v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
Write-Output "PSv2 Feature: $(if($v2){$v2.State}else{'not found'})"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        ps_major = None
        ps_minor = None
        v2_state = ""
        for line in cmd.stdout.splitlines():
            if line.startswith("PSVersion:"):
                v = line.split(":", 1)[1].strip()
                parts = v.split(".")
                try:
                    ps_major = int(parts[0])
                    ps_minor = int(parts[1]) if len(parts) > 1 else 0
                except (ValueError, IndexError):
                    pass
            if line.startswith("PSv2 Feature:"):
                v2_state = line.split(":", 1)[1].strip().lower()

        issues = []
        if ps_major is not None and ps_major < 5:
            issues.append(
                f"PowerShell {ps_major}.{ps_minor} is installed - version 5.1+ is required for full security features"
            )
        if ps_major == 5 and ps_minor < 1:
            issues.append("PowerShell 5.0 detected - upgrade to 5.1 for security fixes")
        if "enabled" in v2_state:
            issues.append(
                "PowerShell 2.0 engine is still installed - it bypasses script block logging and AMSI"
            )

        if issues:
            result.status = STATUS_FAIL
            result.finding = " | ".join(issues)
            result.remediation = (
                "Install Windows Management Framework 5.1 if PS version is below 5.1. "
                "Disable PS 2.0: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root."
            )
        else:
            result.status = STATUS_PASS
            result.finding = f"PowerShell {ps_major}.{ps_minor} is installed and PS 2.0 feature state is: {v2_state}."
            result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
