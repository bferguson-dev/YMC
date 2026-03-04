"""
AU-014_event_forwarding.py
--------------------------
Verifies Windows Event Forwarding (WEF) is configured.

Check ID : AU-014
Category : Audit & Logging
Framework: NIST AU-9, CIS 18.9.26
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


@register_check("AU-014")
def check_event_forwarding(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows Event Forwarding is configured to send logs to a collector."""
    result = base_result(
        connector,
        "AU-014",
        "Windows Event Forwarding",
        "Verify Windows Event Forwarding is configured to forward logs to a central collector.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$sub = wecutil es 2>&1
Write-Output "WEF subscriptions: $($sub -join ', ')"
$svc = Get-Service Wecsvc -ErrorAction SilentlyContinue
Write-Output "WEC service status: $($svc.Status) / $($svc.StartType)"
$winrm = winrm get winrm/config/client 2>&1 | Select-String "AllowUnencrypted"
Write-Output "WinRM AllowUnencrypted: $winrm"
$collector = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager' -ErrorAction SilentlyContinue)
Write-Output "SubscriptionManager policy: $($null -ne $collector)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        has_subs = False
        has_policy = False
        for line in output.splitlines():
            if "WEF subscriptions:" in line:
                val = line.split(":", 1)[1].strip()
                if val and val.lower() not in ("", "none", " "):
                    has_subs = True
            if "SubscriptionManager policy: true" in line.lower():
                has_policy = True

        if has_subs or has_policy:
            result.status = STATUS_PASS
            result.finding = "Windows Event Forwarding is configured. Events are being forwarded to a central collector."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = "Windows Event Forwarding does not appear to be configured. Events are stored locally only."
            result.remediation = (
                "Configure WEF via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Event Forwarding > 'Configure target Subscription Manager'. "
                "Set to your Windows Event Collector server address. "
                "Events stored only locally are at risk of tampering or loss."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
