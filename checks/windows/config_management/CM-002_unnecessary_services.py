"""
CM-002_unnecessary_services.py
------------------------------
Checks for commonly unnecessary and risky services that should be

Check ID : CM-002
Category : Config Management
Framework: NIST CM-7

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


@register_check("CM-002")
def check_unnecessary_services(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks for commonly unnecessary and risky services that should be
    disabled on a hardened Windows Server.
    """
    result = base_result(
        connector,
        "CM-002",
        "Unnecessary Services Disabled",
        "Check for high-risk services that should be disabled on hardened systems.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Unnecessary Service Check ---"
$riskyServices = @(
    'TlntSvr', 'FTPSVC', 'MSFTPSVC', 'RemoteRegistry',
    'Browser', 'SSDPSRV', 'upnphost'
)
$found = @()
foreach ($svcName in $riskyServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Output "  $svcName | Status: $($svc.Status) | StartType: $($svc.StartType)"
        if ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
            $found += $svcName
        }
    }
}
if ($found.Count -eq 0) {
    Write-Output "SERVICE_STATUS: PASS - No flagged services are running or set to auto-start."
} else {
    Write-Output "SERVICE_STATUS: FAIL - Potentially unnecessary services found: $($found -join ', ')"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        if "SERVICE_STATUS: PASS" in cmd.stdout:
            result.status = STATUS_PASS
            result.finding = (
                "No flagged unnecessary services are running or auto-starting."
            )
        elif "SERVICE_STATUS: FAIL" in cmd.stdout:
            result.status = STATUS_FAIL
            result.finding = (
                "One or more unnecessary/risky services are running or not disabled."
            )
            result.remediation = (
                "Disable services that are not required for this system's function:\n"
                "  Set-Service -Name <ServiceName> -StartupType Disabled\n"
                "  Stop-Service -Name <ServiceName> -Force\n"
                "Validate service necessity with the system owner before disabling."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = (
                "Service check completed — review raw evidence for details."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# CM-003 — Default Administrative Shares
# ---------------------------------------------------------------------------
