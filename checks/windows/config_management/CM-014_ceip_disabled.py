"""
CM-014_ceip_disabled.py
------------------------
Verifies the Customer Experience Improvement Program is disabled.

Check ID : CM-014
Category : Configuration Management
Framework: NIST SI-12, CIS 18.9.14
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


@register_check("CM-014")
def check_ceip_disabled(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the Customer Experience Improvement Program (CEIP) is disabled."""
    result = base_result(
        connector,
        "CM-014",
        "Customer Experience Improvement Program Disabled",
        "Verify CEIP is disabled to prevent telemetry data transmission to Microsoft.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$ceip = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows' -Name 'CEIPEnable' -ErrorAction SilentlyContinue).CEIPEnable
Write-Output "CEIPEnable (policy): $ceip  (0=disabled)"
$ceip2 = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\SQMClient\\Windows' -Name 'CEIPEnable' -ErrorAction SilentlyContinue).CEIPEnable
Write-Output "CEIPEnable (direct): $ceip2  (0=disabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        policy_val = None
        direct_val = None
        for line in cmd.stdout.splitlines():
            if "CEIPEnable (policy):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    policy_val = int(v)
                except ValueError:
                    pass
            if "CEIPEnable (direct):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    direct_val = int(v)
                except ValueError:
                    pass

        if policy_val == 0 or direct_val == 0:
            result.status = STATUS_PASS
            result.finding = "Customer Experience Improvement Program is disabled."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"CEIP may be enabled (policy={policy_val}, direct={direct_val}). System usage data may be transmitted to Microsoft."
            result.remediation = (
                "Disable via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Data Collection and Preview Builds > "
                "'Do not send CEIP data'. Or set CEIPEnable=0 in the registry."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
