"""
CM-001_smbv1_disabled.py
------------------------
Verifies SMBv1 is disabled. SMBv1 is the protocol exploited by

Check ID : CM-001
Category : Config Management
Framework: NIST CM-7, CIS 9.1

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


@register_check("CM-001")
def check_smbv1_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Verifies SMBv1 is disabled. SMBv1 is the protocol exploited by
    EternalBlue/WannaCry and has been deprecated since Windows Server 2012 R2.
    """
    result = base_result(
        connector,
        "CM-001",
        "SMBv1 Protocol Disabled",
        "Verify SMBv1 is disabled. SMBv1 is vulnerable to EternalBlue and related exploits.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- SMBv1 Status ---"
# Check server-side SMBv1
$smbConfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Write-Output "SMB1 Server Enabled   : $($smbConfig.EnableSMB1Protocol)"

# Check Windows feature (Server OS)
$feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
if ($feature) {
    Write-Output "SMB1 Feature State    : $($feature.State)"
}

# Check registry
$regVal = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' `
           -Name 'SMB1' -ErrorAction SilentlyContinue).SMB1
Write-Output "Registry SMB1 Value   : $regVal (0=Disabled, 1=Enabled, null=Default)"

if ($smbConfig.EnableSMB1Protocol -eq $false) {
    Write-Output "SMB1_STATUS: PASS - SMBv1 is disabled via server configuration"
} else {
    Write-Output "SMB1_STATUS: FAIL - SMBv1 is ENABLED"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "SMB1_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "SMBv1 is disabled on this host."
        elif "SMB1_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "SMBv1 is ENABLED — this system is vulnerable to EternalBlue-class exploits."
            result.remediation = (
                "Disable SMBv1 immediately:\n"
                "  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                "  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n"
                "Reboot may be required. Verify no legacy systems depend on SMBv1 first."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "SMBv1 status could not be definitively determined. Review raw evidence."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-002 — Unnecessary Services Disabled
# ---------------------------------------------------------------------------
