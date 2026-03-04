"""
SV-002_remote_registry.py
-------------------------
The Remote Registry service allows authenticated users to read and write registry
keys remotely. This should be disabled unless specifically required.

Check ID : SV-002
Category : Services
Framework: NIST CM-7, CIS 5.29
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


@register_check("SV-002")
def check_remote_registry(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the Remote Registry service is disabled."""
    result = base_result(
        connector,
        "SV-002",
        "Remote Registry Service",
        "Verify the Remote Registry service is disabled to prevent remote registry access.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$svc = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output "Status   : $($svc.Status)"
    Write-Output "StartType: $($svc.StartType)"
} else { Write-Output "Status   : not found" }
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
        if "not found" in status:
            result.status = STATUS_PASS
            result.finding = "Remote Registry service is not installed on this system."
            result.remediation = ""
        elif "disabled" in start_type and "stopped" in status:
            result.status = STATUS_PASS
            result.finding = "Remote Registry service is stopped and disabled."
            result.remediation = ""
        elif "running" in status:
            result.status = STATUS_FAIL
            result.finding = (
                "Remote Registry service is RUNNING. Remote registry access is enabled."
            )
            result.remediation = "Disable: Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled."
        else:
            result.status = STATUS_WARNING
            result.finding = f"Remote Registry status={status}, StartType={start_type}. Verify it is fully disabled."
            result.remediation = "Set-Service RemoteRegistry -StartupType Disabled."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
