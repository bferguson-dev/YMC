"""
SV-005_discovery_services.py
-----------------------------
Verifies unnecessary network discovery services are disabled.

Check ID : SV-005
Category : Services
Framework: NIST CM-7, CIS 5.25
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


@register_check("SV-005")
def check_discovery_services(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies unnecessary network discovery services are disabled."""
    result = base_result(
        connector,
        "SV-005",
        "Network Discovery Services Disabled",
        "Verify SSDP, UPnP, and WS-Discovery services are disabled on non-client systems.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$services = @('SSDPSRV','upnphost','FDResPub','fdPHost','WinHttpAutoProxySvc')
foreach ($svcName in $services) {
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Output "$svcName : $($svc.Status) / $($svc.StartType)"
    } else {
        Write-Output "$svcName : not installed"
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        running = []
        for line in cmd.stdout.splitlines():
            if ": Running" in line or ": Automatic" in line:
                svc = line.split(":")[0].strip()
                if svc not in running:
                    running.append(svc)

        if not running:
            result.status = STATUS_PASS
            result.finding = (
                "Network discovery services (SSDP, UPnP, FD) are not running."
            )
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Network discovery services are running: {running}. These expose the system on the local network."
            result.remediation = (
                "Disable unnecessary discovery services: "
                "Stop-Service SSDPSRV, upnphost, FDResPub, fdPHost -Force; "
                "Set-Service <name> -StartupType Disabled. "
                "Required for network discovery features — disable only if not needed."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
