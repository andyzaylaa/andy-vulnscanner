"""Vulnerability checking module for VulnScanner."""

from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""

    port: int
    service: str
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    recommendation: str
    cve: str = ""


class VulnChecker:
    """Check for known vulnerabilities based on scan results."""

    # Known vulnerable service patterns
    VULN_DATABASE: list[dict] = [
        # FTP vulnerabilities
        {
            "port": 21,
            "service": "FTP",
            "patterns": ["vsftpd 2.3.4"],
            "severity": "Critical",
            "title": "vsFTPd 2.3.4 Backdoor",
            "description": "vsFTPd version 2.3.4 contains a backdoor that allows "
            "remote code execution via a specially crafted username.",
            "recommendation": "Upgrade vsFTPd to the latest version immediately.",
            "cve": "CVE-2011-2523",
        },
        {
            "port": 21,
            "service": "FTP",
            "patterns": ["ProFTPD 1.3.3", "ProFTPD 1.3.2"],
            "severity": "High",
            "title": "ProFTPD Remote Code Execution",
            "description": "ProFTPD versions prior to 1.3.4 are vulnerable to "
            "remote code execution via crafted telnet IAC sequences.",
            "recommendation": "Upgrade ProFTPD to version 1.3.4 or later.",
            "cve": "CVE-2011-4130",
        },
        # SSH vulnerabilities
        {
            "port": 22,
            "service": "SSH",
            "patterns": ["OpenSSH_7.2", "OpenSSH_6.", "OpenSSH_5."],
            "severity": "High",
            "title": "OpenSSH Outdated Version",
            "description": "The running OpenSSH version is outdated and may be "
            "vulnerable to multiple known exploits including user "
            "enumeration and authentication bypass.",
            "recommendation": "Upgrade OpenSSH to the latest stable version.",
            "cve": "CVE-2016-6210",
        },
        {
            "port": 22,
            "service": "SSH",
            "patterns": ["OpenSSH_4.", "OpenSSH_3."],
            "severity": "Critical",
            "title": "OpenSSH Critical Vulnerabilities",
            "description": "This OpenSSH version is severely outdated with multiple "
            "critical vulnerabilities including remote code execution.",
            "recommendation": "Upgrade OpenSSH immediately to the latest version.",
            "cve": "Multiple",
        },
        # HTTP vulnerabilities
        {
            "port": 80,
            "service": "HTTP",
            "patterns": ["Apache/2.2.", "Apache/2.0."],
            "severity": "High",
            "title": "Apache HTTP Server Outdated",
            "description": "Apache 2.2.x and 2.0.x have reached end of life and "
            "contain multiple known vulnerabilities.",
            "recommendation": "Upgrade to Apache 2.4.x latest release.",
            "cve": "Multiple",
        },
        {
            "port": 80,
            "service": "HTTP",
            "patterns": ["nginx/1.0", "nginx/0."],
            "severity": "High",
            "title": "Nginx Outdated Version",
            "description": "This Nginx version is outdated and may be vulnerable "
            "to buffer overflow and denial of service attacks.",
            "recommendation": "Upgrade Nginx to the latest stable version.",
            "cve": "Multiple",
        },
        {
            "port": 80,
            "service": "HTTP",
            "patterns": ["Microsoft-IIS/6.", "Microsoft-IIS/5."],
            "severity": "Critical",
            "title": "Microsoft IIS Critical Vulnerability",
            "description": "IIS 5.x/6.x are severely outdated with multiple "
            "critical vulnerabilities including remote code execution.",
            "recommendation": "Upgrade to the latest version of IIS.",
            "cve": "CVE-2017-7269",
        },
        # SMB vulnerabilities
        {
            "port": 445,
            "service": "SMB",
            "patterns": [],
            "severity": "Medium",
            "title": "SMB Service Exposed",
            "description": "SMB (Server Message Block) service is accessible. "
            "This service has a history of critical vulnerabilities "
            "including EternalBlue (MS17-010).",
            "recommendation": "Restrict SMB access to trusted networks only. "
            "Ensure all patches are applied.",
            "cve": "CVE-2017-0144",
        },
        # Telnet
        {
            "port": 23,
            "service": "Telnet",
            "patterns": [],
            "severity": "High",
            "title": "Telnet Service Running",
            "description": "Telnet transmits data including credentials in "
            "plaintext. This is a significant security risk.",
            "recommendation": "Disable Telnet and use SSH instead.",
            "cve": "",
        },
        # MySQL
        {
            "port": 3306,
            "service": "MySQL",
            "patterns": ["5.0.", "5.1.", "4."],
            "severity": "High",
            "title": "MySQL Outdated Version",
            "description": "This MySQL version is outdated and may contain "
            "known vulnerabilities including authentication bypass.",
            "recommendation": "Upgrade MySQL to the latest stable version.",
            "cve": "CVE-2012-2122",
        },
        {
            "port": 3306,
            "service": "MySQL",
            "patterns": [],
            "severity": "Medium",
            "title": "MySQL Externally Accessible",
            "description": "MySQL is accessible from external networks. "
            "Database servers should not be directly exposed.",
            "recommendation": "Restrict MySQL access to localhost or trusted IPs.",
            "cve": "",
        },
        # RDP
        {
            "port": 3389,
            "service": "RDP",
            "patterns": [],
            "severity": "High",
            "title": "RDP Service Exposed",
            "description": "Remote Desktop Protocol is exposed. RDP has had "
            "critical vulnerabilities like BlueKeep (CVE-2019-0708).",
            "recommendation": "Use a VPN for RDP access. Enable NLA and apply patches.",
            "cve": "CVE-2019-0708",
        },
        # VNC
        {
            "port": 5900,
            "service": "VNC",
            "patterns": [],
            "severity": "High",
            "title": "VNC Service Exposed",
            "description": "VNC service is externally accessible. Many VNC "
            "implementations have weak authentication.",
            "recommendation": "Use SSH tunneling for VNC. Restrict network access.",
            "cve": "",
        },
        # Redis
        {
            "port": 6379,
            "service": "Redis",
            "patterns": [],
            "severity": "Critical",
            "title": "Redis Unauthenticated Access",
            "description": "Redis is accessible without authentication by default. "
            "This can lead to data theft and remote code execution.",
            "recommendation": "Enable Redis authentication and restrict network access.",
            "cve": "",
        },
        # MongoDB
        {
            "port": 27017,
            "service": "MongoDB",
            "patterns": [],
            "severity": "Critical",
            "title": "MongoDB Potentially Unauthenticated",
            "description": "MongoDB may be running without authentication. "
            "This is a common misconfiguration that exposes data.",
            "recommendation": "Enable MongoDB authentication and restrict access.",
            "cve": "",
        },
        # PostgreSQL
        {
            "port": 5432,
            "service": "PostgreSQL",
            "patterns": [],
            "severity": "Medium",
            "title": "PostgreSQL Externally Accessible",
            "description": "PostgreSQL is accessible from external networks. "
            "Ensure strong authentication is configured.",
            "recommendation": "Restrict PostgreSQL access. Review pg_hba.conf.",
            "cve": "",
        },
    ]

    def check_vulnerabilities(self, scan_result) -> list[Vulnerability]:
        """Check scan results against the vulnerability database."""
        vulns = []

        for port_result in scan_result.ports:
            if port_result.state != "open":
                continue

            for vuln_entry in self.VULN_DATABASE:
                if not self._port_matches(port_result.port, vuln_entry["port"]):
                    continue

                # If patterns are specified, check banner/version
                if vuln_entry["patterns"]:
                    matched = False
                    combined = (
                        f"{port_result.banner} {port_result.version}"
                    ).lower()
                    for pattern in vuln_entry["patterns"]:
                        if pattern.lower() in combined:
                            matched = True
                            break
                    if not matched:
                        continue

                vuln = Vulnerability(
                    port=port_result.port,
                    service=port_result.service or vuln_entry["service"],
                    severity=vuln_entry["severity"],
                    title=vuln_entry["title"],
                    description=vuln_entry["description"],
                    recommendation=vuln_entry["recommendation"],
                    cve=vuln_entry.get("cve", ""),
                )
                vulns.append(vuln)

        return vulns

    def _port_matches(self, scanned_port: int, vuln_port: int) -> bool:
        """Check if the scanned port matches the vulnerability port."""
        # Direct match
        if scanned_port == vuln_port:
            return True
        # HTTP services can be on multiple ports
        http_ports = {80, 8080, 8443, 8888, 9090}
        if vuln_port == 80 and scanned_port in http_ports:
            return True
        return False

    def get_severity_color(self, severity: str) -> str:
        """Return a hex color for the severity level."""
        colors = {
            "Critical": "#FF0000",
            "High": "#FF6600",
            "Medium": "#FFAA00",
            "Low": "#00AAFF",
            "Info": "#00CC00",
        }
        return colors.get(severity, "#FFFFFF")

    def get_risk_score(self, vulns: list[Vulnerability]) -> tuple[int, str]:
        """Calculate overall risk score from vulnerabilities."""
        if not vulns:
            return 0, "No Issues Found"

        score = 0
        for v in vulns:
            if v.severity == "Critical":
                score += 40
            elif v.severity == "High":
                score += 25
            elif v.severity == "Medium":
                score += 10
            elif v.severity == "Low":
                score += 5
            else:
                score += 1

        score = min(score, 100)

        if score >= 80:
            label = "Critical Risk"
        elif score >= 60:
            label = "High Risk"
        elif score >= 30:
            label = "Medium Risk"
        elif score >= 10:
            label = "Low Risk"
        else:
            label = "Informational"

        return score, label
