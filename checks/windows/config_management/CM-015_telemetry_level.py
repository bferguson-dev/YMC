"""
CM-015_telemetry_level.py
--------------------------
Verifies Windows telemetry data collection level is set appropriately.

Check ID : CM-015
Category : Configuration Management
Framework: NIST SI-12, CIS 18.9.16
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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("CM-015")
def check_telemetry_level(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies Windows telemetry level is set to Security (0) or Basic (1)."""
    result = base_result(
        connector,
        "CM-015",
        "Windows Telemetry Level",
        "Verify Windows telemetry is set to Security or Basic level to minimise data transmission.",
        "Configuration Management",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$tel = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue).AllowTelemetry
Write-Output "AllowTelemetry (policy): $tel  (0=Security/off, 1=Basic, 2=Enhanced, 3=Full)"
$tel2 = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection' -Name 'AllowTelemetry' -ErrorAction SilentlyContinue).AllowTelemetry
Write-Output "AllowTelemetry (direct): $tel2"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        policy_val = None
        direct_val = None
        for line in cmd.stdout.splitlines():
            if "AllowTelemetry (policy):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    policy_val = int(v)
                except ValueError:
                    pass
            if "AllowTelemetry (direct):" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    direct_val = int(v)
                except ValueError:
                    pass

        val = policy_val if policy_val is not None else direct_val
        level_names = {0: "Security (off)", 1: "Basic", 2: "Enhanced", 3: "Full"}
        level_name = level_names.get(val, f"unknown ({val})")

        if val in (0, 1):
            result.status = STATUS_PASS
            result.finding = f"Windows telemetry is set to '{level_name}' — minimal data transmission."
            result.remediation = ""
        elif val in (2, 3):
            result.status = STATUS_FAIL
            result.finding = f"Windows telemetry is set to '{level_name}'. Diagnostic and usage data is transmitted to Microsoft."
            result.remediation = (
                "Reduce via GPO: Computer Configuration > Administrative Templates > "
                "Windows Components > Data Collection and Preview Builds > "
                "'Allow Diagnostic Data'. Set to 0 (Security) or 1 (Basic). "
                "Or set AllowTelemetry=0 in HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection."
            )
        else:
            result.status = STATUS_WARNING
            result.finding = f"Could not determine telemetry level (policy={policy_val}, direct={direct_val}). Default is typically Enhanced."
            result.remediation = (
                "Set AllowTelemetry=0 or 1 via GPO to minimise data transmission."
            )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
