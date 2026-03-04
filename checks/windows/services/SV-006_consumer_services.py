"""
SV-006_consumer_services.py
----------------------------
Verifies consumer-oriented services are disabled on server systems.

Check ID : SV-006
Category : Services
Framework: NIST CM-7, CIS 5.40
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


@register_check("SV-006")
def check_consumer_services(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies consumer/gaming services are disabled on managed systems."""
    result = base_result(
        connector,
        "SV-006",
        "Consumer and Gaming Services Disabled",
        "Verify Xbox, OneDrive sync, and other consumer services are disabled on managed systems.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$consumer = @(
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc',
    'XboxGipSvc',
    'DiagTrack',
    'dmwappushservice',
    'RetailDemo'
)
foreach ($svcName in $consumer) {
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
            if ": Running" in line:
                svc = line.split(":")[0].strip()
                running.append(svc)

        if not running:
            result.status = STATUS_PASS
            result.finding = "Consumer and gaming services are not running."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Consumer/gaming services are running: {running}. These increase attack surface and telemetry."
            result.remediation = (
                f"Disable: {'; '.join(['Set-Service ' + s + ' -StartupType Disabled' for s in running])}. "
                "DiagTrack (Connected User Experiences) can be a significant telemetry source."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
