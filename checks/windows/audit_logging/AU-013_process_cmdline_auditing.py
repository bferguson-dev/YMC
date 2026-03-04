"""
AU-013_process_cmdline_auditing.py
-----------------------------------
Verifies process creation events include full command line arguments.

Check ID : AU-013
Category : Audit & Logging
Framework: NIST AU-3, CIS 17.2.1
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


@register_check("AU-013")
def check_process_cmdline_auditing(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies process creation audit events include full command line arguments."""
    result = base_result(
        connector,
        "AU-013",
        "Process Creation Command Line Auditing",
        "Verify process creation events (Event ID 4688) capture full command line arguments.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$cmdline = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Write-Output "ProcessCreationIncludeCmdLine_Enabled: $cmdline  (1=enabled)"
$audit = auditpol /get /subcategory:"Process Creation" /r 2>&1 | ConvertFrom-Csv | Select-Object -ExpandProperty 'Inclusion Setting'
Write-Output "Process Creation audit: $audit"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        cmdline_val = None
        audit_val = ""
        for line in cmd.stdout.splitlines():
            if "ProcessCreationIncludeCmdLine_Enabled:" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    cmdline_val = int(v)
                except ValueError:
                    pass
            if "Process Creation audit:" in line:
                audit_val = line.split(":", 1)[1].strip().lower()

        proc_audited = "success" in audit_val or "failure" in audit_val
        cmdline_enabled = cmdline_val == 1

        if proc_audited and cmdline_enabled:
            result.status = STATUS_PASS
            result.finding = (
                "Process creation auditing is enabled with full command line capture."
            )
            result.remediation = ""
        elif proc_audited and not cmdline_enabled:
            result.status = STATUS_FAIL
            result.finding = "Process creation is audited (Event 4688) but command line arguments are NOT captured."
            result.remediation = (
                "Enable command line capture: Set "
                "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit "
                "ProcessCreationIncludeCmdLine_Enabled=1. "
                "GPO: Computer Configuration > Administrative Templates > System > Audit Process Creation."
            )
        else:
            result.status = STATUS_FAIL
            result.finding = f"Process creation auditing is not fully enabled (audit={audit_val}, cmdline={cmdline_val})."
            result.remediation = (
                "Enable via auditpol: auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable. "
                "Also enable command line capture: ProcessCreationIncludeCmdLine_Enabled=1."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
