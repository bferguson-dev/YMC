"""
SI-005_os_eol_status.py
------------------------
Verifies the Windows OS version is not past end-of-life.

Check ID : SI-005
Category : System Integrity
Framework: NIST SI-2, CIS 18.1
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

# Known EOL Windows versions (build number -> name)
EOL_BUILDS = {
    7600: "Windows 7 RTM",
    7601: "Windows 7 SP1",
    9200: "Windows 8",
    9600: "Windows 8.1",
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows Server 2016 / Win10 1607",
    15063: "Windows 10 1703",
    16299: "Windows 10 1709",
    17134: "Windows 10 1803",
    17763: None,  # Server 2019 / Win10 1809 — Server 2019 still supported
    18362: "Windows 10 1903",
    18363: "Windows 10 1909",
    19041: None,  # Win10 2004 — check caption
}


@register_check("SI-005")
def check_os_eol_status(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Verifies the installed Windows OS version is still within its support lifecycle."""
    result = base_result(
        connector,
        "SI-005",
        "OS Version End-of-Life Status",
        "Verify the installed Windows version is within Microsoft support lifecycle.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$os = Get-WmiObject Win32_OperatingSystem
Write-Output "Caption    : $($os.Caption)"
Write-Output "Version    : $($os.Version)"
Write-Output "BuildNumber: $($os.BuildNumber)"
Write-Output "ServicePack: $($os.ServicePackMajorVersion)"
$hotfix = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1)
Write-Output "Last hotfix: $($hotfix.HotFixID) installed $($hotfix.InstalledOn)"
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        caption = ""
        build = None
        for line in cmd.stdout.splitlines():
            if line.startswith("Caption    :"):
                caption = line.split(":", 1)[1].strip()
            if line.startswith("BuildNumber:"):
                v = line.split(":", 1)[1].strip()
                try:
                    build = int(v)
                except ValueError:
                    pass

        # Check explicit EOL builds
        if build in EOL_BUILDS and EOL_BUILDS[build] is not None:
            result.status = STATUS_FAIL
            result.finding = f"OS is end-of-life: {caption} (Build {build} = {EOL_BUILDS[build]}). No security patches are available."
            result.remediation = "Upgrade to a supported Windows version immediately. EOL systems cannot be made compliant."
            return result

        # Flag clearly old systems
        eol_keywords = ["2003", "2008", "2012", "Vista", "XP", "NT"]
        if any(k in caption for k in eol_keywords):
            result.status = STATUS_FAIL
            result.finding = f"OS appears to be end-of-life: '{caption}'. This version is no longer supported by Microsoft."
            result.remediation = (
                "Upgrade to Windows Server 2019/2022 or Windows 10/11 immediately."
            )
            return result

        # Check for older Win10 releases that are EOL
        if build and build < 19041 and "10" in caption:
            result.status = STATUS_FAIL
            result.finding = f"Windows 10 Build {build} is end-of-life. OS: {caption}"
            result.remediation = "Update to a supported Windows 10/11 feature release."
            return result

        result.status = STATUS_PASS
        result.finding = f"OS version appears to be within support lifecycle: {caption} (Build {build})."
        result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
