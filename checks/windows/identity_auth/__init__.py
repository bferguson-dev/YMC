"""
IA-004_rdp_nla.py
-----------------
Verifies that Remote Desktop requires Network Level Authentication (NLA).

Check ID : IA-004
Category : Identity & Auth
Framework: NIST IA-2

This file is auto-discovered by the check registry at startup.
To add a new check, create a new file in this directory following
the same pattern â€” no other files need to be modified.
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


@register_check("IA-004")
def check_rdp_nla(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Verifies that Remote Desktop requires Network Level Authentication (NLA).
    NLA forces authentication before the full RDP session is established,
    mitigating several credential theft attack vectors.
    """
    result = base_result(
        connector,
        "IA-004",
        "RDP Network Level Authentication (NLA)",
        "Verify that RDP connections require NLA before session establishment.",
        "Identification and Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Remote Desktop / NLA Configuration ---"

# Check if RDP is enabled
$rdpEnabled = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' `
               -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
Write-Output "RDP Enabled (0=Yes)     : $rdpEnabled"

# Check NLA requirement
$nlaRequired = (Get-ItemProperty `
    'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' `
    -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
Write-Output "NLA Required (1=Yes)    : $nlaRequired"

# Check via WMI
$rdpSettings = Get-CimInstance -Class 'Win32_TSGeneralSetting' `
    -Namespace 'root\\CIMv2\\TerminalServices' -ErrorAction SilentlyContinue |
    Where-Object { $_.TerminalName -eq 'RDP-Tcp' }
if ($rdpSettings) {
    Write-Output "WMI UserAuthenticationRequired: $($rdpSettings.UserAuthenticationRequired)"
}

if ($rdpEnabled -eq 1) {
    Write-Output "RDP_STATUS: INFO - RDP is disabled on this system. NLA check not applicable."
} elseif ($nlaRequired -eq 1) {
    Write-Output "RDP_STATUS: PASS - NLA is required for RDP connections."
} elseif ($nlaRequired -eq 0) {
    Write-Output "RDP_STATUS: FAIL - NLA is NOT required. RDP accepts connections without pre-authentication."
} else {
    Write-Output "RDP_STATUS: WARNING - Could not determine NLA status."
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "RDP_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = "RDP requires Network Level Authentication (NLA)."
        elif "RDP_STATUS: INFO" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "RDP is disabled on this system â€” NLA check not applicable."
            )
        elif "RDP_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = "RDP does not require NLA â€” sessions can be established without pre-authentication."
            result.remediation = (
                "Enable NLA via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Remote Desktop Services > Remote Desktop Session Host > "
                "Security > 'Require user authentication for remote connections by using NLA' = Enabled.\n"
                "Or via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
                "WinStations\\RDP-Tcp > UserAuthentication = 1"
            )
        else:
            result.status = STATUS_WARNING
            result.finding = "RDP/NLA status could not be definitively determined. Review raw evidence."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result
