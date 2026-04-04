"""Shodan & Censys Integration for Andy VulnScanner.

Pulls publicly known open ports and vulnerabilities
for a target using the Shodan API.
"""

import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class IntegrationFinding:
    """Represents a finding from external integrations."""

    scanner: str  # "shodan", "censys"
    severity: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class IntegrationResult:
    """Result of integration lookups."""

    target: str
    findings: list[IntegrationFinding] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    vulns_found: int = 0
    scan_time: float = 0.0


class ShodanScanner:
    """Query Shodan API for target intelligence."""

    SHODAN_API_BASE = "https://api.shodan.io"

    def __init__(
        self,
        api_key: str = "",
        on_finding: Optional[Callable[[IntegrationFinding], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
    ):
        self.api_key = api_key
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def reset(self):
        self._stop_event.clear()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    def _report(self, finding: IntegrationFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helper ──────────────────────────────────────────────────

    def _api_request(self, endpoint: str) -> tuple[int, dict]:
        """Make Shodan API request."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"{self.SHODAN_API_BASE}{endpoint}"
        if "?" in url:
            url += f"&key={self.api_key}"
        else:
            url += f"?key={self.api_key}"

        hdrs = {
            "User-Agent": "AndyVulnScanner/1.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=hdrs)

        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, json.loads(body)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, {"error": body}
        except Exception as e:
            return 0, {"error": str(e)}

    def _resolve_host(self, target: str) -> str:
        """Resolve hostname to IP for Shodan lookup."""
        import socket
        host = target
        if "://" in host:
            host = urllib.parse.urlparse(target).netloc
        if ":" in host:
            host = host.split(":")[0]
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    # ── Main scan entry point ────────────────────────────────────────

    def scan(self, target: str) -> IntegrationResult:
        """Query Shodan for target information."""
        self.reset()
        result = IntegrationResult(target=target)
        start_time = time.time()

        if not self.api_key:
            self._log("Shodan API Key Required", "header")
            self._log(
                "  No Shodan API key provided. Get a free key at:",
                "warning",
            )
            self._log("  https://account.shodan.io/register", "info")
            self._log(
                "  Enter your API key in the Shodan API Key field.", "info",
            )

            finding = IntegrationFinding(
                scanner="shodan",
                severity="Info",
                title="Shodan API Key Not Configured",
                description=(
                    "No Shodan API key provided. Shodan provides valuable "
                    "intelligence about publicly exposed services."
                ),
                evidence="API key field is empty.",
                recommendation=(
                    "Register for a free Shodan account at "
                    "https://account.shodan.io/register and enter "
                    "your API key."
                ),
            )
            result.findings.append(finding)
            self._report(finding)
            result.scan_time = time.time() - start_time
            return result

        # Resolve target to IP
        ip = self._resolve_host(target)
        self._log(f"Starting Shodan Lookup for {target} ({ip})...", "header")

        # 1. Host lookup
        self._log("  Querying Shodan host info...", "info")
        status, data = self._api_request(f"/shodan/host/{ip}")

        if status == 200 and "error" not in data:
            self._process_shodan_host(data, result)
        elif status == 404:
            self._log("  No Shodan data found for this host.", "info")
            finding = IntegrationFinding(
                scanner="shodan",
                severity="Info",
                title=f"No Shodan Data for {ip}",
                description="Shodan has no records for this IP address.",
                recommendation="The host may not have been scanned by Shodan yet.",
            )
            result.findings.append(finding)
            self._report(finding)
        elif status == 401:
            self._log("  Invalid Shodan API key!", "error")
            finding = IntegrationFinding(
                scanner="shodan",
                severity="Info",
                title="Invalid Shodan API Key",
                description="The provided Shodan API key is invalid.",
                recommendation="Check your API key at https://account.shodan.io",
            )
            result.findings.append(finding)
            self._report(finding)
        else:
            error_msg = data.get("error", f"HTTP {status}")
            self._log(f"  Shodan API error: {error_msg}", "error")

        if self._stopped():
            result.scan_time = time.time() - start_time
            return result

        # 2. Check API info (credits remaining)
        self._log("\n  Checking API credits...", "info")
        status, info = self._api_request("/api-info")
        if status == 200:
            credits = info.get("query_credits", "?")
            scan_credits = info.get("scan_credits", "?")
            self._log(f"  Query credits: {credits}", "info")
            self._log(f"  Scan credits: {scan_credits}", "info")

        result.scan_time = time.time() - start_time
        self._log(
            f"\n  Shodan lookup complete. "
            f"Found {len(result.open_ports)} open ports, "
            f"{result.vulns_found} vulnerabilities.", "success",
        )
        return result

    def _process_shodan_host(self, data: dict, result: IntegrationResult):
        """Process Shodan host data."""
        ip = data.get("ip_str", "")
        org = data.get("org", "N/A")
        os_info = data.get("os", "N/A")
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        city = data.get("city", "")
        country = data.get("country_name", "")
        isp = data.get("isp", "")

        result.open_ports = ports

        # General host info
        location = f"{city}, {country}" if city else country
        self._log(f"  IP: {ip}", "info")
        self._log(f"  Organization: {org}", "info")
        self._log(f"  ISP: {isp}", "info")
        self._log(f"  OS: {os_info}", "info")
        self._log(f"  Location: {location}", "info")
        self._log(f"  Open Ports: {ports}", "info")
        if hostnames:
            self._log(f"  Hostnames: {', '.join(hostnames)}", "info")

        finding = IntegrationFinding(
            scanner="shodan",
            severity="Info",
            title=f"Shodan Host Info: {ip}",
            description=(
                f"Host information from Shodan database.\n"
                f"Organization: {org}\n"
                f"ISP: {isp}\n"
                f"OS: {os_info}\n"
                f"Location: {location}"
            ),
            evidence=(
                f"IP: {ip}\n"
                f"Ports: {ports}\n"
                f"Hostnames: {', '.join(hostnames)}"
            ),
            recommendation="Review exposed services and ports.",
        )
        result.findings.append(finding)
        self._report(finding)

        # Report open ports
        if ports:
            severity = "Info"
            if len(ports) > 10:
                severity = "Medium"
            elif len(ports) > 20:
                severity = "High"

            finding = IntegrationFinding(
                scanner="shodan",
                severity=severity,
                title=f"Shodan: {len(ports)} Open Ports Detected",
                description=(
                    f"Shodan reports {len(ports)} publicly visible open ports."
                ),
                evidence=f"Ports: {', '.join(str(p) for p in sorted(ports))}",
                recommendation=(
                    "Review all open ports and close unnecessary ones. "
                    "Use firewall rules to restrict access."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

        # Report vulnerabilities
        if vulns:
            result.vulns_found = len(vulns)
            self._log(f"\n  Known Vulnerabilities: {len(vulns)}", "error")
            for cve in vulns[:20]:  # Limit to 20
                self._log(f"    {cve}", "error")

            finding = IntegrationFinding(
                scanner="shodan",
                severity="High",
                title=f"Shodan: {len(vulns)} Known Vulnerabilities",
                description=(
                    f"Shodan reports {len(vulns)} known vulnerabilities "
                    "associated with services on this host."
                ),
                evidence="\n".join(vulns[:20]),
                recommendation=(
                    "Investigate each CVE and patch affected services. "
                    "Search CVE details at https://nvd.nist.gov/"
                ),
            )
            result.findings.append(finding)
            self._report(finding)

        # Process service banners
        services = data.get("data", [])
        for svc in services[:10]:
            port = svc.get("port", 0)
            transport = svc.get("transport", "tcp")
            product = svc.get("product", "")
            version = svc.get("version", "")
            banner = svc.get("data", "")[:200]

            if product:
                svc_vulns = svc.get("vulns", {})
                severity = "Info"
                if svc_vulns:
                    severity = "Medium"

                finding = IntegrationFinding(
                    scanner="shodan",
                    severity=severity,
                    title=f"Service: {product} {version} on port {port}/{transport}",
                    description=(
                        f"Shodan detected {product} {version} running on "
                        f"port {port}/{transport}."
                    ),
                    evidence=f"Banner: {banner}",
                    recommendation=(
                        f"Ensure {product} is updated to the latest version."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
