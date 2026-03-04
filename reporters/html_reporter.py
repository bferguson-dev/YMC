"""
html_reporter.py
----------------
Generates a clean, audit-ready HTML report from scan results.
Designed to satisfy the evidence requirements of PCI DSS, NIST 800-53,
SOC 2, HIPAA, CMMC, and ISO 27001 audits.

Architecture note: This reporter uses simple string templates intentionally.
Jinja2 is available in requirements.txt for when you're ready to build
a more sophisticated styled report — swap this class for one that loads
a Jinja2 template and nothing else in the codebase changes.
"""

import re

from reporters.base_reporter import BaseReporter
from engine.evidence import (
    HostScanResult,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_WARNING,
    STATUS_ERROR,
)


# Status display config
STATUS_CONFIG = {
    STATUS_PASS: {"label": "PASS", "color": "#2d6a2d", "bg": "#e8f5e8"},
    STATUS_FAIL: {"label": "FAIL", "color": "#8b0000", "bg": "#fdecea"},
    STATUS_WARNING: {"label": "WARN", "color": "#7d5a00", "bg": "#fff8e1"},
    STATUS_ERROR: {"label": "ERROR", "color": "#4a4a4a", "bg": "#f5f5f5"},
}


class HtmlReporter(BaseReporter):
    def generate(self, scan_result: HostScanResult) -> str:
        filepath = self._make_filename(scan_result, "html")
        html = self._build_html(scan_result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        return str(filepath)

    def _build_html(self, r: HostScanResult) -> str:
        tool_name = r.checks[0].tool_name if r.checks else "YMC"
        tool_version = r.checks[0].tool_version if r.checks else "1.0.0"

        # Group checks by category for organized output
        categories: dict[str, list] = {}
        for check in r.checks:
            cat = check.check_category
            categories.setdefault(cat, []).append(check)

        checks_html = ""
        for category, checks in sorted(categories.items()):
            checks_html += f"""
        <div class="category">
            <h2>{self._esc(category)}</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width:90px">Check ID</th>
                        <th style="width:70px">Status</th>
                        <th style="width:220px">Check Name</th>
                        <th>Finding</th>
                        <th style="width:140px">Framework Controls</th>
                    </tr>
                </thead>
                <tbody>
"""
            for check in checks:
                cfg = STATUS_CONFIG.get(check.status, STATUS_CONFIG[STATUS_ERROR])
                mappings_html = "<br>".join(
                    f"<span class='mapping'>{self._esc(k)}: {self._esc(v)}</span>"
                    for k, v in check.framework_mappings.items()
                )
                # Build the expandable evidence row
                evidence_id = f"ev_{re.sub(r'[^0-9a-zA-Z_]', '_', check.check_id)}"
                remediation_html = ""
                if check.remediation:
                    remediation_html = f"""
                        <div class="remediation">
                            <strong>Remediation:</strong><br>
                            <pre>{self._esc(check.remediation)}</pre>
                        </div>"""

                checks_html += f"""
                    <tr class="check-row" onclick="toggle('{evidence_id}')">
                        <td><code>{self._esc(check.check_id)}</code></td>
                        <td>
                            <span class="badge"
                                  style="background:{cfg["bg"]};color:{cfg["color"]};border:1px solid {cfg["color"]}">
                                {cfg["label"]}
                            </span>
                        </td>
                        <td>{self._esc(check.check_name)}</td>
                        <td>{self._esc(check.finding)}</td>
                        <td>{mappings_html}</td>
                    </tr>
                    <tr id="{evidence_id}" class="evidence-row" style="display:none">
                        <td colspan="5">
                            <div class="evidence-block">
                                <p><strong>Description:</strong> {self._esc(check.description)}</p>
                                <p>
                                    <strong>Timestamp (UTC):</strong> {self._esc(check.timestamp_utc)}&nbsp;&nbsp;
                                    <strong>Host:</strong> {self._esc(check.hostname)} ({self._esc(check.ip_address)})&nbsp;&nbsp;
                                    <strong>Run By:</strong> {self._esc(check.executed_by)}
                                </p>
                                <strong>Raw Evidence (collected from target system):</strong>
                                <pre class="raw-evidence">{self._esc(check.raw_evidence or "(no output captured)")}</pre>
                                {remediation_html}
                            </div>
                        </td>
                    </tr>
"""
            checks_html += """
                </tbody>
            </table>
        </div>
"""

        # Summary bar
        pass_pct = r.compliance_percentage
        bar_color = (
            "#2d6a2d"
            if pass_pct >= 80
            else ("#e67e00" if pass_pct >= 60 else "#8b0000")
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YMC Report — {self._esc(r.hostname)}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px;
                color: #222; background: #f4f4f4; padding: 20px; }}
        .container {{ max-width: 1300px; margin: 0 auto; background: white;
                      padding: 30px; border: 1px solid #ddd; }}

        /* Header */
        .report-header {{ border-bottom: 3px solid #003366; padding-bottom: 16px; margin-bottom: 20px; }}
        .report-header h1 {{ font-size: 20px; color: #003366; }}
        .report-header .subtitle {{ color: #555; margin-top: 4px; font-size: 12px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr);
                      gap: 10px; margin-top: 16px; }}
        .meta-item {{ background: #f8f9fa; border: 1px solid #e0e0e0;
                      padding: 10px 14px; border-radius: 4px; }}
        .meta-item .label {{ font-size: 10px; text-transform: uppercase;
                             color: #666; letter-spacing: 0.5px; }}
        .meta-item .value {{ font-weight: 600; margin-top: 2px; font-size: 13px; }}

        /* Summary */
        .summary {{ margin: 20px 0; }}
        .summary h2 {{ font-size: 14px; color: #003366; margin-bottom: 10px;
                       text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-row {{ display: flex; gap: 10px; margin-bottom: 12px; }}
        .stat {{ flex: 1; padding: 12px; border-radius: 4px; text-align: center; border: 1px solid; }}
        .stat .num {{ font-size: 24px; font-weight: 700; }}
        .stat .lbl {{ font-size: 10px; text-transform: uppercase; margin-top: 2px; }}
        .stat-pass  {{ background: #e8f5e8; border-color: #2d6a2d; color: #2d6a2d; }}
        .stat-fail  {{ background: #fdecea; border-color: #8b0000; color: #8b0000; }}
        .stat-warn  {{ background: #fff8e1; border-color: #7d5a00; color: #7d5a00; }}
        .stat-error {{ background: #f5f5f5; border-color: #4a4a4a; color: #4a4a4a; }}

        /* Compliance bar */
        .compliance-bar-outer {{ background: #e0e0e0; border-radius: 4px;
                                  height: 20px; overflow: hidden; margin-bottom: 6px; }}
        .compliance-bar-inner {{ height: 100%; background: {bar_color};
                                  width: {pass_pct}%; transition: width 0.3s; }}
        .compliance-label {{ font-size: 12px; color: #333; }}

        /* Category sections */
        .category {{ margin-top: 24px; }}
        .category h2 {{ font-size: 13px; font-weight: 700; color: #003366;
                        text-transform: uppercase; letter-spacing: 0.5px;
                        border-bottom: 1px solid #ccc; padding-bottom: 6px;
                        margin-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #003366; color: white; padding: 8px 10px;
              text-align: left; font-size: 11px; font-weight: 600;
              text-transform: uppercase; letter-spacing: 0.3px; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee;
              vertical-align: top; }}
        .check-row:hover {{ background: #f0f4ff; cursor: pointer; }}
        .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 11px;
                  font-weight: 700; white-space: nowrap; }}
        .mapping {{ display: inline-block; font-size: 10px; background: #eef;
                    border: 1px solid #cce; padding: 1px 5px; border-radius: 3px;
                    margin: 1px 0; white-space: nowrap; }}

        /* Evidence block */
        .evidence-row td {{ background: #fafafa; padding: 0; }}
        .evidence-block {{ padding: 14px 20px; border-top: 1px dashed #ccc; }}
        .evidence-block p {{ margin-bottom: 8px; line-height: 1.5; }}
        pre.raw-evidence {{ background: #1e1e1e; color: #d4d4d4;
                            padding: 12px; border-radius: 4px; overflow-x: auto;
                            font-size: 11px; line-height: 1.6; margin: 8px 0;
                            white-space: pre-wrap; word-break: break-all; }}
        .remediation {{ margin-top: 10px; background: #fff8e1;
                        border-left: 4px solid #f0ad4e; padding: 10px 14px; }}
        .remediation pre {{ margin-top: 6px; background: transparent;
                            color: #333; padding: 0; font-size: 11px; white-space: pre-wrap; }}

        /* Footer */
        .footer {{ margin-top: 30px; padding-top: 14px; border-top: 1px solid #ddd;
                   font-size: 11px; color: #888; }}

        /* Print */
        @media print {{
            .check-row:hover {{ background: white; }}
            .evidence-row {{ display: table-row !important; }}
            pre.raw-evidence {{ background: #f5f5f5; color: #222; }}
        }}
    </style>
    <script>
        function toggle(id) {{
            var el = document.getElementById(id);
            el.style.display = (el.style.display === 'none') ? 'table-row' : 'none';
        }}
        function expandAll() {{
            document.querySelectorAll('.evidence-row').forEach(function(el) {{
                el.style.display = 'table-row';
            }});
        }}
        function collapseAll() {{
            document.querySelectorAll('.evidence-row').forEach(function(el) {{
                el.style.display = 'none';
            }});
        }}
    </script>
</head>
<body>
<div class="container">

    <!-- Header / Chain of Custody -->
    <div class="report-header">
        <h1>{self._esc(tool_name)} v{self._esc(tool_version)} — Evidence Report</h1>
        <p class="subtitle">
            This report contains automated YMC scan evidence collected from the target system.
            Each check row contains the timestamp, executing account, and raw system output
            required for audit substantiation.
        </p>
        <div class="meta-grid">
            <div class="meta-item">
                <div class="label">Target Host</div>
                <div class="value">{self._esc(r.hostname)}</div>
            </div>
            <div class="meta-item">
                <div class="label">IP Address</div>
                <div class="value">{self._esc(r.ip_address)}</div>
            </div>
            <div class="meta-item">
                <div class="label">Compliance Profile</div>
                <div class="value">{self._esc(r.profile_name)}</div>
            </div>
            <div class="meta-item">
                <div class="label">Scan Started (UTC)</div>
                <div class="value">{self._esc(r.scan_start_utc)}</div>
            </div>
            <div class="meta-item">
                <div class="label">Scan Completed (UTC)</div>
                <div class="value">{self._esc(r.scan_end_utc)}</div>
            </div>
            <div class="meta-item">
                <div class="label">Executed By</div>
                <div class="value">{self._esc(r.executed_by)}</div>
            </div>
        </div>
    </div>

    <!-- Summary -->
    <div class="summary">
        <h2>Scan Summary</h2>
        <div class="stat-row">
            <div class="stat stat-pass">
                <div class="num">{r.passed}</div>
                <div class="lbl">Passed</div>
            </div>
            <div class="stat stat-fail">
                <div class="num">{r.failed}</div>
                <div class="lbl">Failed</div>
            </div>
            <div class="stat stat-warn">
                <div class="num">{r.warnings}</div>
                <div class="lbl">Warnings</div>
            </div>
            <div class="stat stat-error">
                <div class="num">{r.errors}</div>
                <div class="lbl">Errors</div>
            </div>
        </div>
        <div class="compliance-bar-outer">
            <div class="compliance-bar-inner"></div>
        </div>
        <div class="compliance-label">
            <strong>{pass_pct}% compliant</strong>
            ({r.passed} of {r.passed + r.failed + r.warnings} actionable checks passed)
        </div>
    </div>

    <!-- Controls -->
    <div style="margin:14px 0; font-size:12px;">
        <a href="#" onclick="expandAll(); return false;">&#9660; Expand All Evidence</a>
        &nbsp;|&nbsp;
        <a href="#" onclick="collapseAll(); return false;">&#9650; Collapse All</a>
        &nbsp;&nbsp;<em style="color:#888">(Click any row to expand raw evidence)</em>
    </div>

    <!-- Check results by category -->
    {checks_html}

    <!-- Footer -->
    <div class="footer">
        <p>
            Generated by <strong>{self._esc(tool_name)} {self._esc(tool_version)}</strong>
            &nbsp;|&nbsp; Profile: {self._esc(r.profile_name)}
            &nbsp;|&nbsp; Host: {self._esc(r.hostname)} ({self._esc(r.ip_address)})
            &nbsp;|&nbsp; {self._esc(r.scan_start_utc)} UTC
            &nbsp;|&nbsp; Run by: {self._esc(r.executed_by)}
        </p>
        <p style="margin-top:6px; color:#aaa;">
            Raw evidence in each check row was collected directly from the target system
            via authenticated WinRM session. Timestamps reflect UTC collection time.
        </p>
    </div>

</div>
</body>
</html>"""

    def _esc(self, text) -> str:
        """HTML-escapes a string to prevent XSS in report output."""
        if text is None:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
