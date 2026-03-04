"""
AU-006_remote_log_forwarding.py
-------------------------------
Checks whether Windows Event Forwarding (WEF) subscriptions are configured,

Check ID : AU-006
Category : Audit & Logging
Framework: NIST AU-9

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
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AU-006")
def check_remote_log_forwarding(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks whether Windows Event Forwarding (WEF) subscriptions are configured,
    or if a third-party log forwarding agent (e.g. Splunk UF, NXLog) is running.
    """
    result = base_result(
        connector,
        "AU-006",
        "Remote Log Forwarding",
        "Verify that logs are being forwarded to a centralized log management system.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Remote Log Forwarding Check ---"

# Check Windows Event Forwarding subscriptions
$wefSubs = wecutil es 2>$null
if ($wefSubs) {
    Write-Output "WEF Subscriptions Found:"
    $wefSubs | ForEach-Object { Write-Output "  - $_" }
    Write-Output "WEF_STATUS: CONFIGURED"
} else {
    Write-Output "WEF_STATUS: NOT_CONFIGURED"
}

# Check for common third-party log forwarding agents
$agents = @(
    @{Name='SplunkUniversalForwarder'; Service='SplunkForwarder'},
    @{Name='NXLog';                    Service='nxlog'},
    @{Name='Elastic Agent';            Service='Elastic Agent'},
    @{Name='Filebeat';                 Service='filebeat'},
    @{Name='Winlogbeat';               Service='winlogbeat'},
    @{Name='Fluentd';                  Service='fluentdwinsvc'}
)

$foundAgents = @()
foreach ($agent in $agents) {
    $svc = Get-Service -Name $agent.Service -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        $foundAgents += "$($agent.Name) (Running)"
    }
}

if ($foundAgents.Count -gt 0) {
    Write-Output "Log Forwarding Agents Running:"
    $foundAgents | ForEach-Object { Write-Output "  - $_" }
    Write-Output "AGENT_STATUS: CONFIGURED"
} else {
    Write-Output "AGENT_STATUS: NONE_DETECTED"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr

        wef_configured = "WEF_STATUS: CONFIGURED" in cmd.stdout
        agent_configured = "AGENT_STATUS: CONFIGURED" in cmd.stdout

        if wef_configured or agent_configured:
            result.status = STATUS_PASS
            result.finding = "Log forwarding is configured on this host."
        else:
            result.status = STATUS_FAIL
            result.finding = (
                "No remote log forwarding detected. Logs exist only on the local system "
                "and may be overwritten or lost."
            )
            result.remediation = (
                "Configure Windows Event Forwarding (WEF) to a Windows Event Collector, "
                "or deploy a log forwarding agent (Splunk UF, Elastic Agent, NXLog, Filebeat) "
                "to ship logs to a centralized SIEM."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result
