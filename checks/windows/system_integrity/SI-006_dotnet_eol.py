"""
SI-006_dotnet_eol.py
---------------------
Identifies end-of-life .NET Framework versions installed on the system.

Check ID : SI-006
Category : System Integrity
Framework: NIST SI-2, CIS 18.2
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


@register_check("SI-006")
def check_dotnet_eol(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Identifies end-of-life .NET Framework versions that no longer receive security updates."""
    result = base_result(
        connector,
        "SI-006",
        ".NET Framework EOL Version Detection",
        "Identify installed .NET Framework versions that are end-of-life and no longer patched.",
        "System Integrity",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
Write-Output "--- Installed .NET Framework Versions ---"
$netVersions = @()
$paths = @(
    'HKLM:\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP'
)
foreach ($p in $paths) {
    Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = $_.GetValue("Version")
        $sp  = $_.GetValue("SP")
        $rel = $_.GetValue("Release")
        if ($ver) { Write-Output "  $($_.PSChildName): Version=$ver SP=$sp Release=$rel" }
        $_.OpenSubKey("Client") | ForEach-Object {
            if ($_) {
                $cv = $_.GetValue("Version")
                if ($cv) { Write-Output "    Client: $cv" }
            }
        }
        $_.OpenSubKey("Full") | ForEach-Object {
            if ($_) {
                $fv = $_.GetValue("Version")
                $fr = $_.GetValue("Release")
                if ($fv) { Write-Output "    Full: $fv (Release $fr)" }
            }
        }
    }
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout

        # .NET Framework 3.5 with SP1 on modern Windows gets OS-level updates — flag as warning
        # .NET 4.x below 4.8 are EOL (4.8 is the last .NET Framework release)
        eol_found = []
        warned = []

        for line in output.splitlines():
            line_lower = line.lower()
            for eol in ["v1.0", "v1.1", "v2.0"]:
                if eol in line_lower:
                    eol_found.append(line.strip())
            if "v4." in line_lower:
                # Check for old 4.x releases (below 4.8 = Release 528040)
                import re

                rel_match = re.search(r"release\s+(\d+)", line_lower)
                if rel_match:
                    rel_num = int(rel_match.group(1))
                    if rel_num < 528040:  # 528040 = .NET 4.8
                        warned.append(f"{line.strip()} (pre-4.8, consider upgrading)")

        if eol_found:
            result.status = STATUS_FAIL
            result.finding = f"End-of-life .NET Framework versions found: {eol_found}"
            result.remediation = (
                "Remove or upgrade EOL .NET Framework versions. "
                ".NET Framework 1.x and 2.x are no longer supported. "
                "Use Control Panel > Programs > Turn Windows features on or off to remove."
            )
        elif warned:
            result.status = STATUS_WARNING
            result.finding = f".NET Framework versions older than 4.8 detected. These may not receive all security updates: {warned}"
            result.remediation = (
                "Upgrade to .NET Framework 4.8 or later. Download from Microsoft."
            )
        else:
            result.status = STATUS_PASS
            result.finding = "No end-of-life .NET Framework versions detected."
            result.remediation = ""

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
