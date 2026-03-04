"""
SV-007_iis_hardening.py
------------------------
Checks IIS installation status and basic hardening if IIS is present.

Check ID : SV-007
Category : Services
Framework: NIST CM-7, CIS 18.9.70
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


@register_check("SV-007")
def check_iis_hardening(
    connector: WinRMConnector,
    settings: dict,
    tool_name: str,
    tool_version: str,
    executed_by: str,
) -> CheckResult:
    """Checks IIS status and basic hardening configuration if installed."""
    result = base_result(
        connector,
        "SV-007",
        "IIS Installation and Hardening",
        "Verify IIS is not installed unless required, and if installed basic hardening is applied.",
        "Services",
        tool_name,
        tool_version,
        executed_by,
    )

    ps_script = """
$svc = Get-Service W3SVC -ErrorAction SilentlyContinue
Write-Output "IIS (W3SVC) service: $(if($svc){$svc.Status + ' / ' + $svc.StartType}else{'not installed'})"
$iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction SilentlyContinue
if (-not $iisFeature) {
    $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
}
Write-Output "IIS feature state: $(if($iisFeature){$iisFeature.State}else{'not found'})"
if ($svc -and $svc.Status -eq 'Running') {
    Write-Output "--- IIS Hardening Checks ---"
    $anon = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -ErrorAction SilentlyContinue).Value
    Write-Output "Anonymous authentication: $anon"
    $dirBrowse = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/directoryBrowse' -name 'enabled' -ErrorAction SilentlyContinue).Value
    Write-Output "Directory browsing: $dirBrowse"
    $serverHeader = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter 'system.webServer/security/requestFiltering' -name 'removeServerHeader' -ErrorAction SilentlyContinue).Value
    Write-Output "Server header removed: $serverHeader"
}
"""

    try:
        cmd = connector.run_ps(ps_script)
        result.raw_evidence = cmd.stdout or cmd.stderr
        output = cmd.stdout
        iis_installed = (
            "not installed" not in output.lower() and "not found" not in output.lower()
        )
        iis_running = "Running" in output

        if not iis_installed or not iis_running:
            result.status = STATUS_PASS
            result.finding = "IIS is not installed or not running on this system."
            result.remediation = ""
        else:
            issues = []
            for line in output.splitlines():
                if "Anonymous authentication: True" in line:
                    issues.append("Anonymous authentication is enabled on default site")
                if "Directory browsing: True" in line:
                    issues.append(
                        "Directory browsing is enabled â€” exposes file structure"
                    )
                if "Server header removed: False" in line:
                    issues.append(
                        "Server version header not removed â€” discloses IIS version"
                    )

            if issues:
                result.status = STATUS_FAIL
                result.finding = (
                    "IIS is installed with hardening issues: " + " | ".join(issues)
                )
                result.remediation = (
                    "Harden IIS: Disable anonymous auth for sensitive paths, "
                    "disable directory browsing, remove server version header. "
                    "Follow CIS IIS Benchmark for full hardening guidance."
                )
            else:
                result.status = STATUS_WARNING
                result.finding = "IIS is running. Verify it is required and review full IIS hardening configuration."
                result.remediation = (
                    "If IIS is not required, disable it: "
                    "Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole. "
                    "If required, follow CIS IIS Benchmark for hardening."
                )

    except WinRMExecutionError as e:
        result.status = STATUS_ERROR
        result.raw_evidence = str(e)
        result.finding = f"Check execution failed: {e}"
        result.remediation = "Verify WinRM connectivity and account permissions."

    return result
