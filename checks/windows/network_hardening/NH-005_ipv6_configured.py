"""
NH-005_ipv6_configured.py
-------------------------
Attackers can use IPv6 to bypass IPv4-based security controls.
If IPv6 is not required, disabling it reduces the attack surface.

Check ID : NH-005
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.1
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


@register_check("NH-005")
def check_ipv6_configured(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies IPv6 is disabled or properly configured if not in use."""
    result = base_result(
        connector,
        "NH-005",
        "IPv6 Configuration",
        "Verify IPv6 is disabled on interfaces where it is not in use.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- IPv6 per adapter ---"
$adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
if ($adapters) {
    $enabled = $adapters | Where-Object { $_.Enabled -eq $true }
    Write-Output "IPv6 enabled on $($enabled.Count) of $($adapters.Count) adapters"
    $adapters | ForEach-Object {
        Write-Output "  $($_.Name): Enabled=$($_.Enabled)"
    }
} else {
    Write-Output "Could not query IPv6 adapter binding"
}
$prefer6 = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name 'DisabledComponents' -ErrorAction SilentlyContinue).DisabledComponents
Write-Output "DisabledComponents (IPv6): $prefer6  (0xFF = disabled completely)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        disabled_val = None
        for line in output.splitlines():
            if "DisabledComponents (IPv6):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    disabled_val = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        enabled_count = 0
        for line in output.splitlines():
            if "IPv6 enabled on" in line:
                try:
                    enabled_count = int(line.split()[3])
                except (TypeError, ValueError, IndexError):
                    pass
        if disabled_val == 255 or enabled_count == 0:
            result.status = STATUS_PASS
            result.finding = "IPv6 is disabled or not bound to any active adapter."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"IPv6 is enabled on {enabled_count} adapter(s). If IPv6 is not required, consider disabling it."
            result.remediation = (
                "If IPv6 is not needed: Set HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters "
                "DisabledComponents=0xFF (255) and reboot. "
                "Or disable per-adapter via network adapter properties."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
