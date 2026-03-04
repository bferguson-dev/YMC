"""
CM-012_dotnet_strong_name_bypass.py
-------------------------------------
Verifies .NET strong name verification bypass is disabled.

Check ID : CM-012
Category : Configuration Management
Framework: NIST CM-7, CIS 18.3.5
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


@register_check("CM-012")
def check_dotnet_strong_name_bypass(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies .NET strong name verification bypass is not enabled."""
    result = base_result(
        connector,
        "CM-012",
        ".NET Strong Name Verification Bypass Disabled",
        "Verify .NET strong name verification bypass is not configured.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$bypass = @()
$paths = @(
    'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\AllowStrongNameBypass',
    'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\AllowStrongNameBypass'
)
foreach ($p in $paths) {
    $val = (Get-ItemProperty $p -ErrorAction SilentlyContinue).AllowStrongNameBypass
    if ($val -ne $null) {
        Write-Output "Path: $p"
        Write-Output "AllowStrongNameBypass: $val  (0=disabled/safe)"
        $bypass += $val
    }
}
if ($bypass.Count -eq 0) { Write-Output "AllowStrongNameBypass: not set (default allows bypass in some scenarios)" }
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        bypass_values = []
        for line in output.splitlines():
            if "AllowStrongNameBypass:" in line and "Path:" not in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    bypass_values.append(int(v))
                except ValueError:
                    pass

        if not bypass_values:
            result.status = STATUS_WARNING
            result.finding = "AllowStrongNameBypass not explicitly set. Default behavior allows bypass in full-trust scenarios."
            result.remediation = (
                "Explicitly disable: Set HKLM:\\SOFTWARE\\Microsoft\\.NETFramework "
                "AllowStrongNameBypass=0 (DWORD). "
                "Repeat for Wow6432Node path for 32-bit .NET on 64-bit systems."
            )
        elif any(v == 1 for v in bypass_values):
            result.status = STATUS_FAIL
            result.finding = f"AllowStrongNameBypass is ENABLED (values: {bypass_values}). .NET strong name verification can be bypassed."
            result.remediation = (
                "Disable: Set AllowStrongNameBypass=0 in "
                "HKLM:\\SOFTWARE\\Microsoft\\.NETFramework and "
                "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework."
            )
        else:
            result.status = STATUS_PASS
            result.finding = f".NET strong name verification bypass is disabled (values: {bypass_values})."
            result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
