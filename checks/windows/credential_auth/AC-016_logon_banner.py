"""
AC-016_logon_banner.py
----------------------
A logon banner is required by most compliance frameworks to notify users of
authorized use policies and legal consequences of unauthorized access.

Check ID : AC-016
Category : Credential & Authentication
Framework: NIST AC-8, PCI DSS 12.9, CIS 1.5
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


@register_check("AC-016")
def check_logon_banner(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies a legal notice banner is configured for interactive logon."""
    result = base_result(
        connector,
        "AC-016",
        "Legal Notice / Logon Banner",
        "Verify a legal notice caption and message are configured for interactive logon.",
        "Credential & Authentication",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$caption = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
$text    = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
Write-Output "Caption length: $($caption.Length)"
Write-Output "Text length   : $($text.Length)"
Write-Output "Caption       : $caption"
Write-Output "Text          : $text"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        cap_len = 0
        txt_len = 0
        for line in output.splitlines():
            if line.startswith("Caption length:"):
                try:
                    cap_len = int(line.split(":", 1)[1].strip())
                except (TypeError, ValueError, IndexError):
                    pass
            if line.startswith("Text length"):
                try:
                    txt_len = int(line.split(":", 1)[1].strip())
                except (TypeError, ValueError, IndexError):
                    pass
        if cap_len > 0 and txt_len > 0:
            result.status = STATUS_PASS
            result.finding = f"Legal notice banner is configured (caption: {cap_len} chars, text: {txt_len} chars)."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = "Legal notice banner is NOT configured. No logon warning message is displayed."
            result.remediation = (
                "Configure via GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "'Interactive logon: Message title for users attempting to log on' and "
                "'Interactive logon: Message text for users attempting to log on'."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
