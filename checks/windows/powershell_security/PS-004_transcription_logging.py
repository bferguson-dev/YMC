"""
PS-004_transcription_logging.py
-------------------------------
Transcription captures all PowerShell input and output to a text file,
creating a full audit trail of every interactive and scripted session.

Check ID : PS-004
Category : PowerShell Security
Framework: NIST AU-3, CIS 18.9.98
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


@register_check("PS-004")
def check_ps_transcription_logging(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies PowerShell Transcription Logging is enabled."""
    result = base_result(
        connector,
        "PS-004",
        "PowerShell Transcription Logging",
        "Verify PowerShell transcription logging is enabled to record full session transcripts.",
        "PowerShell Security",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$tl = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name 'EnableTranscripting' -ErrorAction SilentlyContinue).EnableTranscripting
$dir = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -Name 'OutputDirectory' -ErrorAction SilentlyContinue).OutputDirectory
Write-Output "EnableTranscripting: $tl  (1=enabled)"
Write-Output "OutputDirectory    : $dir"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        tl = None
        for line in cmd.stdout.splitlines():
            if line.startswith("EnableTranscripting:"):
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    tl = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        if tl == 1:
            result.status = STATUS_PASS
            result.finding = "PowerShell Transcription Logging is enabled."
            result.remediation = ""
        else:
            result.status = STATUS_FAIL
            result.finding = (
                f"PowerShell Transcription Logging is NOT enabled (value: {tl})."
            )
            result.remediation = (
                "Enable via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Windows PowerShell > 'Turn on PowerShell Transcription'. "
                "Configure OutputDirectory to a secure, centralized log path."
            )
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
