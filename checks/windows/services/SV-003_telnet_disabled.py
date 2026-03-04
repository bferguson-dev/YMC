"""
SV-003_telnet_disabled.py
-------------------------
Telnet transmits all data including credentials in plaintext.
It should never be present on any system in a managed environment.

Check ID : SV-003
Category : Services
Framework: NIST CM-7, CIS 5.3
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


@register_check("SV-003")
def check_telnet_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Telnet client and server features are disabled."""
    result = base_result(
        connector,
        "SV-003",
        "Telnet Client/Server Disabled",
        "Verify Telnet is not installed — it transmits credentials and data in plaintext.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$client = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
$server = Get-WindowsOptionalFeature -Online -FeatureName TelnetServer -ErrorAction SilentlyContinue
Write-Output "TelnetClient State: $($client.State)"
Write-Output "TelnetServer State: $($server.State)"
$svc = Get-Service TlntSvr -ErrorAction SilentlyContinue
Write-Output "TlntSvr service: $(if($svc){'present - '+$svc.Status}else{'not present'})"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout.lower()
        client_enabled = "telnetclient state: enabled" in output
        server_enabled = "telnetserver state: enabled" in output
        svc_running = "present - running" in output
        issues = []
        if client_enabled:
            issues.append("Telnet Client feature is installed")
        if server_enabled:
            issues.append("Telnet Server feature is installed")
        if svc_running:
            issues.append("TlntSvr service is running")
        if issues:
            result.status = STATUS_FAIL
            result.finding = (
                " | ".join(issues) + ". Telnet transmits credentials in plaintext."
            )
            result.remediation = (
                "Remove Telnet: Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient. "
                "Use SSH (OpenSSH is built into Windows 10/Server 2019+) as a replacement."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "Telnet client and server are not installed."
            result.remediation = ""
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
