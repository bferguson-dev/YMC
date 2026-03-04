"""
NH-004_wpad_disabled.py
-----------------------
WPAD can be abused via LLMNR/NBT-NS poisoning to redirect web traffic through
an attacker-controlled proxy, enabling credential theft and MITM attacks.

Check ID : NH-004
Category : Network Hardening
Framework: NIST CM-7, CIS 18.5.7
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


@register_check("NH-004")
def check_wpad_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Web Proxy Auto-Discovery (WPAD) is disabled."""
    result = base_result(
        connector,
        "NH-004",
        "WPAD Disabled",
        "Verify WPAD is disabled to prevent proxy auto-discovery attacks.",
        "Network Hardening",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$wpad = (Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad' -Name 'WpadOverride' -ErrorAction SilentlyContinue).WpadOverride
Write-Output "WPAD WpadOverride (HKCU): $wpad  (1=disabled)"
$proxy = (Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name 'AutoDetect' -ErrorAction SilentlyContinue).AutoDetect
Write-Output "AutoDetect (WPAD): $proxy  (0=disabled)"
$svc = Get-Service WinHttpAutoProxySvc -ErrorAction SilentlyContinue
Write-Output "WinHttpAutoProxySvc: $($svc.Status) / $($svc.StartType)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        auto_detect = None
        for line in output.splitlines():
            if "AutoDetect (WPAD):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    auto_detect = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if auto_detect == 0:
            result.status = STATUS_PASS
            result.finding = "WPAD auto-detection is disabled."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"WPAD auto-detection may be enabled (AutoDetect={auto_detect}). Proxy hijacking attacks are possible."
            result.remediation = (
                "Disable WPAD: Set HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings "
                "AutoDetect=0. Also disable via IE/Edge proxy settings and consider disabling WinHttpAutoProxySvc."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
