"""
SV-001_print_spooler.py
-----------------------
The Print Spooler service has multiple critical RCE and privilege escalation
vulnerabilities (PrintNightmare). It should be disabled on non-print servers.

Check ID : SV-001
Category : Services
Framework: NIST CM-7, CVE-2021-1675, CVE-2021-34527
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


@register_check("SV-001")
def check_print_spooler(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the Print Spooler service is disabled on non-print-server systems."""
    result = base_result(
        connector,
        "SV-001",
        "Print Spooler Service",
        "Verify Print Spooler is disabled on systems that do not require print services.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$svc = Get-Service Spooler -ErrorAction SilentlyContinue
Write-Output "Status   : $($svc.Status)"
Write-Output "StartType: $($svc.StartType)"
$sharing = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -ErrorAction SilentlyContinue).RegisterSpoolerRemoteRpcEndPoint
Write-Output "RemoteSpooler (RPC): $sharing  (2=disabled)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        status = ""
        start_type = ""
        for line in output.splitlines():
            if line.startswith("Status   :"):
                status = line.split(":", 1)[1].strip().lower()
            if line.startswith("StartType:"):
                start_type = line.split(":", 1)[1].strip().lower()
        if "stopped" in status and "disabled" in start_type:
            result.status = STATUS_PASS
            result.finding = "Print Spooler service is stopped and disabled."
            result.remediation = ""
        elif "running" in status:
            result.status = STATUS_FAIL
            result.finding = "Print Spooler service is RUNNING. This is a PrintNightmare (CVE-2021-34527) attack vector on non-print servers."
            result.remediation = (
                "Disable: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled. "
                "If printing is required, implement Point and Print restrictions (see EM-005)."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"Print Spooler status={status}, StartType={start_type}. Verify it is fully disabled."
            result.remediation = "Set-Service Spooler -StartupType Disabled to ensure it cannot be started."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
