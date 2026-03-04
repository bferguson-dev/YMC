"""
SR-003_crash_dump_config.py
---------------------------
Full memory dumps (Complete Memory Dump) contain all system memory at crash time,
including credentials cached in LSASS. Production systems should use smaller dump types.

Check ID : SR-003
Category : Storage & Recovery
Framework: NIST SC-28, CIS 18.3.3
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


@register_check("SR-003")
def check_crash_dump_config(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies crash dump settings do not produce full memory dumps in production."""
    result = base_result(
        connector,
        "SR-003",
        "Crash Dump Configuration",
        "Verify crash dump settings do not save full memory images containing credentials.",
        "Storage & Recovery",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$dump = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -ErrorAction SilentlyContinue
Write-Output "CrashDumpEnabled : $($dump.CrashDumpEnabled)  (0=disabled,1=complete,2=kernel,3=small,7=auto)"
Write-Output "DumpFile         : $($dump.DumpFile)"
Write-Output "AutoReboot       : $($dump.AutoReboot)"
Write-Output "LogEvent         : $($dump.LogEvent)"
"""
    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        dump_type = None
        for line in cmd.stdout.splitlines():
            if "CrashDumpEnabled :" in line:
                v = line.split(":", 1)[1].strip().split()[0]
                try:
                    dump_type = int(v)
                except (TypeError, ValueError, IndexError):
                    pass
        type_names = {
            0: "disabled",
            1: "complete/full",
            2: "kernel",
            3: "small",
            7: "automatic",
        }
        name = type_names.get(dump_type, f"unknown({dump_type})")
        if dump_type == 1:
            result.status = STATUS_FAIL
            result.finding = "Crash dump is set to 'Complete/Full' memory dump. Full memory dumps contain credentials and sensitive data."
            result.remediation = (
                "Change to kernel or small dump: Set HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl "
                "CrashDumpEnabled=2 (kernel) or 3 (small). "
                "GPO: Computer Configuration > Administrative Templates > System > "
                "'Choose how BitLocker-protected operating system drives can be recovered'."
            )
        elif dump_type in (0, 2, 3, 7):
            result.status = STATUS_PASS
            result.finding = f"Crash dump is set to '{name}' â€” does not capture full memory contents."
            result.remediation = ""
        else:
            result.status = STATUS_WARNING
            result.finding = f"Crash dump type is '{name}'. Review to ensure it does not expose sensitive memory."
            result.remediation = "Verify CrashDumpEnabled is set to 0 (disabled), 2 (kernel), or 3 (small)."
    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
