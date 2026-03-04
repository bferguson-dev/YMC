"""
AC-012_credential_guard.py
--------------------------
Credential Guard uses Virtualization Based Security to isolate NTLM hashes and
Kerberos tickets in a hypervisor-protected container, preventing pass-the-hash attacks.

Check ID : AC-012
Category : Credential & Authentication
Framework: NIST IA-5, CIS 3.2
"""

import logging
from checks.windows.common import (
    base_result,
    register_check,
    WinRMConnector,
    WinRMExecutionError,
    CheckResult,
    STATUS_PASS,
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AC-012")
def check_credential_guard(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Credential Guard is enabled to protect credentials in a VBS container."""
    result = base_result(
        connector,
        "AC-012",
        "Windows Defender Credential Guard",
        "Verify Credential Guard is enabled to isolate credentials from privileged code.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$ls = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags
Write-Output "LsaCfgFlags: $ls"
try {
    $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue
    if ($cg) { Write-Output "SecurityServicesRunning: $($cg.SecurityServicesRunning)" }
    else { Write-Output "SecurityServicesRunning: unavailable" }
} catch { Write-Output "SecurityServicesRunning: unavailable" }
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        lsa_cfg = ""
        ssr = ""
        for line in output.splitlines():
            if line.startswith("LsaCfgFlags:"):
                lsa_cfg = line.split(":", 1)[1].strip()
            if line.startswith("SecurityServicesRunning:"):
                ssr = line.split(":", 1)[1].strip()
        cg_enabled = lsa_cfg in ("1", "2") or "1" in ssr
        if cg_enabled:
            result.status = STATUS_PASS
            result.finding = "Credential Guard is enabled. Credentials are isolated in a VBS container."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Credential Guard does not appear to be enabled (LsaCfgFlags={lsa_cfg or 'not set'}). Credentials may be exposed to pass-the-hash attacks."
            result.remediation = (
                "Enable via GPO: Computer Configuration > Administrative Templates > "
                "System > Device Guard > Turn On Virtualization Based Security. "
                "Requires UEFI, Secure Boot, 64-bit Windows 10/Server 2016+."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
