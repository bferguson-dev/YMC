"""
AU-012_dns_query_logging.py
---------------------------
DNS query logs are critical for detecting C2 communication, data exfiltration,
and malware callbacks. Should be enabled and forwarded to SIEM.

Check ID : AU-012
Category : Audit & Logging
Framework: NIST AU-2, CIS 18.9.19
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


@register_check("AU-012")
def check_dns_query_logging(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies DNS query logging is enabled for threat detection."""
    result = base_result(
        connector,
        "AU-012",
        "DNS Query Logging",
        "Verify DNS client query logging is enabled to support threat detection and forensics.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$dns = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableLogFileRollover' -ErrorAction SilentlyContinue)
Write-Output "DNS Policy key exists: $($null -ne $dns)"
$etw = Get-WinEvent -ListProvider "Microsoft-Windows-DNS-Client" -ErrorAction SilentlyContinue
Write-Output "DNS-Client ETW provider: $($null -ne $etw)"
$log = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($log) { Write-Output "DNS-Client/Operational log: has events, last: $($log.TimeCreated)" }
else { Write-Output "DNS-Client/Operational log: no events or disabled" }
$logEnabled = (Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" -ErrorAction SilentlyContinue).IsEnabled
Write-Output "DNS-Client/Operational enabled: $logEnabled"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        enabled = False
        for line in output.splitlines():
            if "DNS-Client/Operational enabled:" in line:
                if "true" in line.lower():
                    enabled = True
        if enabled:
            result.status = STATUS_PASS
            result.finding = "DNS Client operational logging is enabled."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = "DNS Client operational logging is not enabled. DNS queries are not being logged."
            result.remediation = (
                "Enable via PowerShell: "
                "wevtutil set-log Microsoft-Windows-DNS-Client/Operational /enabled:true. "
                "Forward to SIEM for threat detection of C2 and data exfiltration via DNS."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
