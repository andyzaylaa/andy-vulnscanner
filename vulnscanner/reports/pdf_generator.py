"""PDF Report Generator for Andy VulnScanner.

Generates professional vulnerability assessment reports in PDF format
using only the Python standard library (no external dependencies).
Outputs a styled HTML file that can be printed/saved as PDF.
"""

import html
import os
from datetime import datetime
from typing import Any


class PDFReportGenerator:
    """Generate professional vulnerability assessment reports."""

    SEVERITY_COLORS = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8",
        "Info": "#28a745",
    }

    SEVERITY_ORDER = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
    }

    def generate(
        self,
        filepath: str,
        target: str,
        scan_results: dict[str, Any],
        findings: list[dict[str, str]],
    ) -> str:
        """Generate a professional PDF-style HTML report.

        Args:
            filepath: Output file path (will be .html)
            target: Scan target
            scan_results: Dict of scan result data
            findings: List of finding dicts with keys:
                scanner, severity, title, description, evidence, recommendation

        Returns:
            Path to generated report file.
        """
        # Ensure .html extension
        if not filepath.endswith(".html"):
            filepath = filepath.rsplit(".", 1)[0] + ".html" if "." in filepath else filepath + ".html"

        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "Info"), 4),
        )

        # Count severities
        severity_counts: dict[str, int] = {}
        for f in sorted_findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)
        risk_level = self._risk_level(risk_score)
        risk_color = self._risk_color(risk_score)

        # Generate HTML report
        report_html = self._build_report(
            target=target,
            scan_results=scan_results,
            findings=sorted_findings,
            severity_counts=severity_counts,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_color=risk_color,
        )

        # Write to file
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report_html)

        return filepath

    def _calculate_risk_score(self, severity_counts: dict[str, int]) -> int:
        """Calculate overall risk score (0-100)."""
        weights = {
            "Critical": 25,
            "High": 15,
            "Medium": 8,
            "Low": 3,
            "Info": 0,
        }
        score = 0
        for sev, count in severity_counts.items():
            score += weights.get(sev, 0) * count
        return min(100, score)

    def _risk_level(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    def _risk_color(self, score: int) -> str:
        if score >= 75:
            return "#dc3545"
        if score >= 50:
            return "#fd7e14"
        if score >= 25:
            return "#ffc107"
        if score > 0:
            return "#17a2b8"
        return "#28a745"

    def _build_report(
        self,
        target: str,
        scan_results: dict[str, Any],
        findings: list[dict[str, str]],
        severity_counts: dict[str, int],
        risk_score: int,
        risk_level: str,
        risk_color: str,
    ) -> str:
        """Build the full HTML report."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_findings = len(findings)

        # Build severity chart bars
        chart_html = ""
        max_count = max(severity_counts.values()) if severity_counts else 1
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = severity_counts.get(sev, 0)
            pct = (count / max_count * 100) if max_count > 0 else 0
            color = self.SEVERITY_COLORS.get(sev, "#666")
            chart_html += f"""
                <div class="chart-row">
                    <span class="chart-label">{sev}</span>
                    <div class="chart-bar-bg">
                        <div class="chart-bar" style="width:{pct}%;background:{color};"></div>
                    </div>
                    <span class="chart-count">{count}</span>
                </div>"""

        # Build findings table
        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Info")
            color = self.SEVERITY_COLORS.get(sev, "#666")
            scanner = html.escape(f.get("scanner", ""))
            title = html.escape(f.get("title", ""))
            desc = html.escape(f.get("description", ""))
            evidence = html.escape(f.get("evidence", ""))
            rec = html.escape(f.get("recommendation", ""))

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-id">#{i}</span>
                    <span class="severity-badge" style="background:{color};">{sev}</span>
                    <span class="finding-scanner">[{scanner}]</span>
                    <span class="finding-title">{title}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-section">
                        <strong>Description:</strong>
                        <p>{desc}</p>
                    </div>"""

            if evidence:
                findings_html += f"""
                    <div class="finding-section">
                        <strong>Evidence:</strong>
                        <pre class="evidence">{evidence}</pre>
                    </div>"""

            if rec:
                findings_html += f"""
                    <div class="finding-section">
                        <strong>Recommendation:</strong>
                        <p class="recommendation">{rec}</p>
                    </div>"""

            findings_html += """
                </div>
            </div>"""

        # Build executive summary
        exec_summary = self._executive_summary(
            target, total_findings, severity_counts, risk_level,
        )

        # Scan details
        scan_details = ""
        for key, value in scan_results.items():
            safe_key = html.escape(str(key))
            safe_val = html.escape(str(value))
            scan_details += f"""
                <tr><td><strong>{safe_key}</strong></td><td>{safe_val}</td></tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Andy VulnScanner - Vulnerability Assessment Report</title>
    <style>
        @media print {{
            body {{ background: white !important; }}
            .no-print {{ display: none !important; }}
            .page-break {{ page-break-before: always; }}
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}

        /* Cover */
        .cover {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 60px 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .cover h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .cover .subtitle {{ font-size: 1.3em; color: #8ec5fc; margin-bottom: 30px; }}
        .cover .meta {{ color: #aaa; font-size: 0.95em; }}
        .cover .meta span {{ margin: 0 15px; }}

        /* Risk Score */
        .risk-score-box {{
            display: inline-block;
            margin-top: 30px;
            padding: 20px 40px;
            border-radius: 12px;
            background: rgba(255,255,255,0.1);
            border: 2px solid {risk_color};
        }}
        .risk-score-box .score {{
            font-size: 3em;
            font-weight: bold;
            color: {risk_color};
        }}
        .risk-score-box .label {{
            font-size: 1.1em;
            color: {risk_color};
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        /* Sections */
        .section {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }}
        .section h2 {{
            color: #1a1a2e;
            font-size: 1.5em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}

        /* Chart */
        .chart-row {{
            display: flex;
            align-items: center;
            margin: 8px 0;
        }}
        .chart-label {{ width: 80px; font-weight: 600; font-size: 0.9em; }}
        .chart-bar-bg {{
            flex: 1;
            height: 24px;
            background: #f0f0f0;
            border-radius: 4px;
            overflow: hidden;
            margin: 0 10px;
        }}
        .chart-bar {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s;
        }}
        .chart-count {{ width: 40px; text-align: right; font-weight: bold; }}

        /* Summary Grid */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            border: 1px solid #e0e0e0;
        }}
        .summary-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .summary-card .label {{
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
        }}

        /* Findings */
        .finding-card {{
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin: 15px 0;
            overflow: hidden;
        }}
        .finding-header {{
            background: #f8f9fa;
            padding: 12px 15px;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .finding-id {{ font-weight: bold; color: #666; }}
        .severity-badge {{
            color: white;
            padding: 3px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .finding-scanner {{ color: #888; font-size: 0.85em; }}
        .finding-title {{ font-weight: 600; color: #333; }}
        .finding-body {{ padding: 15px; }}
        .finding-section {{ margin: 10px 0; }}
        .finding-section p {{ color: #555; margin-top: 5px; }}
        .evidence {{
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.85em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
            margin-top: 5px;
        }}
        .recommendation {{
            color: #0f3460 !important;
            background: #e8f4f8;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #17a2b8;
        }}

        /* Table */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{ background: #f8f9fa; font-weight: 600; }}

        /* Footer */
        .footer {{
            text-align: center;
            color: #999;
            padding: 30px;
            font-size: 0.85em;
        }}

        /* Print button */
        .print-btn {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #1a1a2e;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }}
        .print-btn:hover {{ background: #0f3460; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Cover -->
        <div class="cover">
            <h1>Vulnerability Assessment Report</h1>
            <div class="subtitle">Andy VulnScanner</div>
            <div class="meta">
                <span>Target: {html.escape(target)}</span>
                <span>Date: {now}</span>
            </div>
            <div class="risk-score-box">
                <div class="score">{risk_score}</div>
                <div class="label">Risk: {risk_level}</div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{exec_summary}</p>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="value">{total_findings}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="summary-card">
                    <div class="value" style="color:#dc3545;">{severity_counts.get("Critical", 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card">
                    <div class="value" style="color:#fd7e14;">{severity_counts.get("High", 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card">
                    <div class="value" style="color:#ffc107;">{severity_counts.get("Medium", 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card">
                    <div class="value" style="color:#17a2b8;">{severity_counts.get("Low", 0)}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>

        <!-- Severity Distribution -->
        <div class="section">
            <h2>Severity Distribution</h2>
            {chart_html}
        </div>

        <!-- Scan Details -->
        <div class="section">
            <h2>Scan Details</h2>
            <table>
                <tr><td><strong>Target</strong></td><td>{html.escape(target)}</td></tr>
                <tr><td><strong>Report Generated</strong></td><td>{now}</td></tr>
                <tr><td><strong>Total Findings</strong></td><td>{total_findings}</td></tr>
                <tr><td><strong>Risk Score</strong></td><td>{risk_score}/100 ({risk_level})</td></tr>
                {scan_details}
            </table>
        </div>

        <!-- Detailed Findings -->
        <div class="section page-break">
            <h2>Detailed Findings ({total_findings})</h2>
            {findings_html if findings_html else '<p style="color:#28a745;">No vulnerabilities found.</p>'}
        </div>

        <!-- Disclaimer -->
        <div class="section">
            <h2>Disclaimer</h2>
            <p style="color:#666; font-size:0.9em;">
                This report was generated by Andy VulnScanner and is intended for
                authorized security assessments only. The findings are based on
                automated scanning and may contain false positives. Manual
                verification is recommended for all findings. Use this tool
                responsibly and only on systems you have permission to test.
            </p>
        </div>

        <div class="footer">
            <p>Andy VulnScanner &mdash; Professional Vulnerability Assessment</p>
            <p>Report generated on {now}</p>
        </div>
    </div>

    <button class="print-btn no-print" onclick="window.print()">
        Save as PDF / Print
    </button>
</body>
</html>"""

    def _executive_summary(
        self,
        target: str,
        total: int,
        severity_counts: dict[str, int],
        risk_level: str,
    ) -> str:
        """Generate executive summary text."""
        critical = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)

        summary = (
            f"A comprehensive vulnerability assessment was conducted against "
            f"<strong>{html.escape(target)}</strong>. The scan identified "
            f"<strong>{total}</strong> findings across multiple categories. "
        )

        if critical > 0:
            summary += (
                f"<strong style='color:#dc3545;'>{critical} critical "
                f"vulnerabilit{'y was' if critical == 1 else 'ies were'} "
                f"found that require{'s' if critical == 1 else ''} "
                f"immediate attention.</strong> "
            )

        if high > 0:
            summary += (
                f"{high} high-severity issue{'s were' if high > 1 else ' was'} "
                f"also identified. "
            )

        summary += (
            f"The overall risk level is rated as <strong>{risk_level}</strong>. "
            "It is recommended to address all critical and high findings "
            "as a priority."
        )

        return summary
