"""
NH-012_smb_signing.py
----------------------
Verifies SMB signing is required on both client and server.

Check ID : NH-012
Category : Network Hardening
Framework: NIST SC-8, CIS 2.3.9
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


@register_check("NH-012")
def check_smb_signing(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies SMB signing is required on both SMB client and server."""
    result = base_result(
        connector,
        "NH-012",
        "SMB Signing Required",
        "Verify SMB packet signing is required on both client and server to prevent MITM attacks.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$srvRequired  = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
$srvEnabled   = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'EnableSecuritySignature' -ErrorAction SilentlyContinue).EnableSecuritySignature
$clntRequired = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
$clntEnabled  = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' -Name 'EnableSecuritySignature' -ErrorAction SilentlyContinue).EnableSecuritySignature
Write-Output "Server RequireSecuritySignature : $srvRequired   (1=required)"
Write-Output "Server EnableSecuritySignature  : $srvEnabled    (1=enabled)"
Write-Output "Client RequireSecuritySignature : $clntRequired  (1=required)"
Write-Output "Client EnableSecuritySignature  : $clntEnabled   (1=enabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        srv_req = None
        clnt_req = None
        for line in cmd.stdout.splitlines():
            if "Server RequireSecuritySignature :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    srv_req = int(v)
                except ValueError:
                    pass
            if "Client RequireSecuritySignature :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    clnt_req = int(v)
                except ValueError:
                    pass

        findings = []
        if srv_req != 1:
            findings.append(
                f"SMB Server signing NOT required (RequireSecuritySignature={srv_req})"
            )
        if clnt_req != 1:
            findings.append(
                f"SMB Client signing NOT required (RequireSecuritySignature={clnt_req})"
            )

        if findings:
            result.status = STATUS_FAIL
            result.finding = (
                " | ".join(findings) + ". SMB relay and MITM attacks are possible."
            )
            result.remediation = (
                "Require SMB signing: Set RequireSecuritySignature=1 for both "
                "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters and "
                "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters. "
                "GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > "
                "Security Options > 'Microsoft network server/client: Digitally sign communications (always)'."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "SMB signing is required on both client and server."
            result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
