"""
json_reporter.py
----------------
Outputs scan results as structured JSON — machine-readable, suitable for
ingestion into a SIEM, GRC platform, or ticketing system.
"""

import json
from reporters.base_reporter import BaseReporter
from engine.evidence import HostScanResult


class JsonReporter(BaseReporter):
    def generate(self, scan_result: HostScanResult) -> str:
        output = {
            "report_metadata": {
                "tool_name": scan_result.checks[0].tool_name
                if scan_result.checks
                else "YMC",
                "tool_version": scan_result.checks[0].tool_version
                if scan_result.checks
                else "1.0.0",
                "profile_name": scan_result.profile_name,
                "hostname": scan_result.hostname,
                "ip_address": scan_result.ip_address,
                "executed_by": scan_result.executed_by,
                "scan_start_utc": scan_result.scan_start_utc,
                "scan_end_utc": scan_result.scan_end_utc,
            },
            "summary": {
                "total_checks": scan_result.total,
                "passed": scan_result.passed,
                "failed": scan_result.failed,
                "warnings": scan_result.warnings,
                "errors": scan_result.errors,
                "compliance_percentage": scan_result.compliance_percentage,
            },
            "checks": [c.to_dict() for c in scan_result.checks],
        }

        filepath = self._make_filename(scan_result, "json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        return str(filepath)
