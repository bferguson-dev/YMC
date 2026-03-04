"""
AU-007_advanced_audit_policy.py
-------------------------------
Checks advanced audit policy categories beyond basic logon/privilege use:

Check ID : AU-007
Category : Audit & Logging
Framework: NIST AU-2

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
    STATUS_WARNING,
    STATUS_ERROR,
)

logger = logging.getLogger(__name__)


@register_check("AU-007")
def check_advanced_audit_policy(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """
    Checks advanced audit policy categories beyond basic logon/privilege use:
    - Object Access (file/registry access)
    - Process Creation (command-line logging)
    - Policy Change
    - System events
    Uses auditpol.exe which reflects the effective policy.
    """
    result = base_result(
        connector,
        "AU-007",
        "Advanced Audit Policy Configuration",
        "Verify advanced audit policy covers object access, process creation, and policy changes.",
        "Audit & Logging",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Advanced Audit Policy (auditpol) ---"
$auditpol = auditpol /get /category:* 2>&1
$auditpol | ForEach-Object { Write-Output $_ }

Write-Output ""
Write-Output "--- Command Line Process Auditing ---"
$cmdline = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
Write-Output "CommandLine in ProcessCreation events: $cmdline  (1 = enabled)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        failures = []

        # Check key categories — auditpol output format:
        # "  Object Access                  Success and Failure" etc.
        required = {
            "Object Access": False,
            "Process Creation": False,
            "Audit Policy Change": False,
            "System": False,
        }

        for line in output.splitlines():
            for category in required:
                if category in line and ("Success" in line or "Failure" in line):
                    required[category] = True

        for category, found in required.items():
            if not found:
                failures.append(f"{category} auditing not configured")

        cmdline_enabled = "CommandLine in ProcessCreation events: 1" in output

        if failures:
            result.status = STATUS_FAIL
            result.finding = (
                f"Missing audit categories: {', '.join(failures)}. "
                f"Command-line logging: {'Enabled' if cmdline_enabled else 'NOT enabled'}."
            )
            result.remediation = (
                "Configure via auditpol.exe or GPO: Computer Configuration > "
                "Windows Settings > Security Settings > Advanced Audit Policy. "
                "Enable Process Creation with command-line logging for forensic capability."
            )
        else:
            result.status = STATUS_PASS if cmdline_enabled else STATUS_WARNING
            result.finding = (
                "Required audit categories are configured. "
                f"Command-line logging: {'Enabled' if cmdline_enabled else 'NOT enabled — recommended'}."
            )
            if not cmdline_enabled:
                result.remediation = (
                    "Enable command-line logging: HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System\\Audit — set ProcessCreationIncludeCmdLine_Enabled = 1."
                )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"

    return result


# ---------------------------------------------------------------------------
# AU-008 — Sysmon Presence
# ---------------------------------------------------------------------------
