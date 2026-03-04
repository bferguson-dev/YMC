"""
NH-013_rdp_encryption.py
------------------------
Verifies RDP encryption level is set to High or FIPS compliant.

Check ID : NH-013
Category : Network Hardening
Framework: NIST SC-8, CIS 18.9.65
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


@register_check("NH-013")
def check_rdp_encryption(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies RDP session encryption is set to High or FIPS compliant level."""
    result = base_result(
        connector,
        "NH-013",
        "RDP Encryption Level",
        "Verify RDP connection encryption is set to High (3) or FIPS Compliant (4).",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$enc = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel
Write-Output "MinEncryptionLevel: $enc  (1=Low, 2=Client Compatible, 3=High, 4=FIPS)"
$security = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'SecurityLayer' -ErrorAction SilentlyContinue).SecurityLayer
Write-Output "SecurityLayer     : $security  (0=RDP, 1=Negotiate, 2=SSL/TLS)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        enc_level = None
        sec_layer = None
        for line in cmd.stdout.splitlines():
            if "MinEncryptionLevel:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    enc_level = int(v)
                except ValueError:
                    pass
            if "SecurityLayer     :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    sec_layer = int(v)
                except ValueError:
                    pass

        level_names = {1: "Low", 2: "Client Compatible", 3: "High", 4: "FIPS Compliant"}
        level_name = level_names.get(enc_level, f"unknown ({enc_level})")

        if enc_level in (3, 4) and sec_layer == 2:
            result.status = STATUS_PASS
            result.finding = (
                f"RDP encryption is '{level_name}' with SSL/TLS security layer."
            )
            result.remediation = ""
        elif enc_level in (3, 4):
            result.status = STATUS_WARNING
            result.finding = f"RDP encryption level is '{level_name}' but security layer is {sec_layer} (SSL/TLS not enforced)."
            result.remediation = "Set SecurityLayer=2 (SSL/TLS required) in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp."
        elif enc_level in (1, 2):
            result.status = STATUS_FAIL
            result.finding = f"RDP encryption level is '{level_name}' â€” insufficient for compliance. Session data may be intercepted."
            result.remediation = (
                "Set MinEncryptionLevel=3 (High) or 4 (FIPS) and SecurityLayer=2 via GPO: "
                "Computer Configuration > Administrative Templates > Windows Components > "
                "Remote Desktop Services > RDP Security > Set client connection encryption level."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"RDP encryption level not explicitly set (enc={enc_level}, sec={sec_layer}). Default may be insufficient."
            result.remediation = (
                "Explicitly set MinEncryptionLevel=3 and SecurityLayer=2 via GPO."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
