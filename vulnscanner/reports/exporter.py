"""Report export module for VulnScanner."""

import csv
from datetime import datetime


class ReportExporter:
    """Export scan results to various formats."""

    @staticmethod
    def to_csv(scan_result, vulnerabilities, filepath: str) -> str:
        """Export scan results to CSV file."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Scan info
            writer.writerow(["Andy VulnScanner - Scan Report"])
            writer.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["Target", scan_result.target])
            writer.writerow(["IP Address", scan_result.ip_address])
            writer.writerow(["Hostname", scan_result.hostname])
            writer.writerow([])

            # Open ports
            writer.writerow(["=== Open Ports ==="])
            writer.writerow(["Port", "State", "Service", "Version", "Banner"])
            for port in scan_result.ports:
                writer.writerow([
                    port.port,
                    port.state,
                    port.service,
                    port.version,
                    port.banner[:100],
                ])
            writer.writerow([])

            # Vulnerabilities
            writer.writerow(["=== Vulnerabilities ==="])
            writer.writerow([
                "Port", "Service", "Severity", "Title",
                "Description", "Recommendation", "CVE",
            ])
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.port,
                    vuln.service,
                    vuln.severity,
                    vuln.title,
                    vuln.description,
                    vuln.recommendation,
                    vuln.cve,
                ])

        return filepath

    @staticmethod
    def to_html(scan_result, vulnerabilities, filepath: str) -> str:
        """Export scan results to HTML report."""
        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#17a2b8",
            "Info": "#28a745",
        }

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Andy VulnScanner Report - {scan_result.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            color: #58a6ff;
            font-size: 2em;
            margin-bottom: 5px;
        }}
        h2 {{
            color: #8b949e;
            font-size: 1.4em;
            margin: 25px 0 15px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }}
        .header {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .meta {{ color: #8b949e; font-size: 0.9em; margin-top: 10px; }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .info-card {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px;
        }}
        .info-card label {{ color: #8b949e; font-size: 0.8em; text-transform: uppercase; }}
        .info-card .value {{ color: #f0f6fc; font-size: 1.1em; margin-top: 5px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 20px;
        }}
        th {{
            background: #21262d;
            color: #f0f6fc;
            padding: 12px 15px;
            text-align: left;
            font-weight: 600;
        }}
        td {{ padding: 10px 15px; border-top: 1px solid #30363d; }}
        tr:hover {{ background: #1c2128; }}
        .severity {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            color: #fff;
        }}
        .port-open {{
            color: #3fb950;
            font-weight: 600;
        }}
        .footer {{
            text-align: center;
            color: #484f58;
            padding: 20px;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Andy VulnScanner Report</h1>
            <p class="meta">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="info-grid">
                <div class="info-card">
                    <label>Target</label>
                    <div class="value">{scan_result.target}</div>
                </div>
                <div class="info-card">
                    <label>IP Address</label>
                    <div class="value">{scan_result.ip_address}</div>
                </div>
                <div class="info-card">
                    <label>Hostname</label>
                    <div class="value">{scan_result.hostname or 'N/A'}</div>
                </div>
                <div class="info-card">
                    <label>Open Ports</label>
                    <div class="value">{len(scan_result.ports)}</div>
                </div>
                <div class="info-card">
                    <label>Vulnerabilities</label>
                    <div class="value">{len(vulnerabilities)}</div>
                </div>
            </div>
        </div>

        <h2>Open Ports</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version / Banner</th>
                </tr>
            </thead>
            <tbody>"""

        for port in scan_result.ports:
            version_info = port.version or port.banner[:80] or "N/A"
            html += f"""
                <tr>
                    <td><strong>{port.port}</strong></td>
                    <td><span class="port-open">{port.state}</span></td>
                    <td>{port.service}</td>
                    <td>{version_info}</td>
                </tr>"""

        if not scan_result.ports:
            html += """
                <tr><td colspan="4" style="text-align:center; color:#8b949e;">
                    No open ports found
                </td></tr>"""

        html += """
            </tbody>
        </table>

        <h2>Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Title</th>
                    <th>CVE</th>
                </tr>
            </thead>
            <tbody>"""

        for vuln in vulnerabilities:
            color = severity_colors.get(vuln.severity, "#6e7681")
            html += f"""
                <tr>
                    <td><span class="severity" style="background:{color};">
                        {vuln.severity}
                    </span></td>
                    <td>{vuln.port}</td>
                    <td>{vuln.service}</td>
                    <td>
                        <strong>{vuln.title}</strong><br>
                        <small style="color:#8b949e;">{vuln.description}</small><br>
                        <small style="color:#58a6ff;">Fix: {vuln.recommendation}</small>
                    </td>
                    <td>{vuln.cve or 'N/A'}</td>
                </tr>"""

        if not vulnerabilities:
            html += """
                <tr><td colspan="5" style="text-align:center; color:#3fb950;">
                    No vulnerabilities detected
                </td></tr>"""

        html += """
            </tbody>
        </table>

        <div class="footer">
            <p>Andy VulnScanner &mdash; Defensive Security Tool</p>
            <p>Use responsibly and only on systems you have permission to test.</p>
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    @staticmethod
    def to_text(scan_result, vulnerabilities) -> str:
        """Generate a plain text summary."""
        lines = []
        lines.append("=" * 60)
        lines.append("  ANDY VULNSCANNER - SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"  Target:     {scan_result.target}")
        lines.append(f"  IP:         {scan_result.ip_address}")
        lines.append(f"  Hostname:   {scan_result.hostname or 'N/A'}")
        lines.append(f"  Open Ports: {len(scan_result.ports)}")
        lines.append(f"  Vulns:      {len(vulnerabilities)}")
        lines.append("=" * 60)
        lines.append("")

        lines.append("OPEN PORTS:")
        lines.append("-" * 50)
        for p in scan_result.ports:
            version = p.version or p.banner[:60] or ""
            lines.append(f"  {p.port:>5}/tcp  {p.state:<8}  {p.service:<15}  {version}")
        if not scan_result.ports:
            lines.append("  No open ports found.")
        lines.append("")

        lines.append("VULNERABILITIES:")
        lines.append("-" * 50)
        for v in vulnerabilities:
            lines.append(f"  [{v.severity}] {v.title}")
            lines.append(f"    Port: {v.port} ({v.service})")
            lines.append(f"    {v.description}")
            lines.append(f"    Fix: {v.recommendation}")
            if v.cve:
                lines.append(f"    CVE: {v.cve}")
            lines.append("")
        if not vulnerabilities:
            lines.append("  No vulnerabilities detected.")

        return "\n".join(lines)
