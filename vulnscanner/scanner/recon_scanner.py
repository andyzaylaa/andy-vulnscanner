"""OSINT & Reconnaissance scanner for Andy VulnScanner.

Includes WHOIS lookup, DNS Recon, and Email Harvester.
"""

import re
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class ReconFinding:
    """Represents a single recon finding."""

    scanner: str  # "whois", "dns", "email"
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class ReconScanResult:
    """Result of a recon scan."""

    target: str
    findings: list[ReconFinding] = field(default_factory=list)
    dns_records_found: int = 0
    emails_found: int = 0
    whois_info: str = ""
    scan_time: float = 0.0


class ReconScanner:
    """Perform WHOIS, DNS recon, and email harvesting."""

    # DNS record types to query
    DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    # Common email patterns on web pages
    EMAIL_PATTERNS = [
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    ]

    # Pages to scrape for emails
    EMAIL_SCRAPE_PATHS = [
        "/", "/contact", "/about", "/team", "/support",
        "/impressum", "/legal", "/privacy",
        "/about-us", "/contact-us", "/our-team",
    ]

    def __init__(
        self,
        timeout: float = 5.0,
        on_finding: Optional[Callable[[ReconFinding], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
    ):
        self.timeout = timeout
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

    def _report(self, finding: ReconFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helper ──────────────────────────────────────────────────

    def _make_request(
        self, url: str, timeout: Optional[float] = None,
    ) -> tuple[int, str]:
        """Make an HTTP request and return (status, body)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        hdrs = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
                "Gecko/20100101 Firefox/115.0"
            ),
        }
        req = urllib.request.Request(url, headers=hdrs)
        tout = timeout or self.timeout

        try:
            with urllib.request.urlopen(req, timeout=tout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body
        except Exception:
            return 0, ""

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _extract_domain(self, target: str) -> str:
        """Extract base domain from target."""
        url = self._normalize_url(target)
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    # ── Main scan entry point ────────────────────────────────────────

    def scan(
        self,
        target: str,
        whois: bool = True,
        dns_recon: bool = True,
        email_harvest: bool = True,
    ) -> ReconScanResult:
        """Run all selected recon scans against the target."""
        self.reset()
        domain = self._extract_domain(target)
        result = ReconScanResult(target=domain)

        total = sum([whois, dns_recon, email_harvest])
        current = 0

        if whois and not self._stopped():
            self._log("Starting WHOIS Lookup...", "header")
            self._scan_whois(domain, result)
            current += 1
            self._progress(current, total)

        if dns_recon and not self._stopped():
            self._log("\nStarting DNS Reconnaissance...", "header")
            self._scan_dns(domain, result)
            current += 1
            self._progress(current, total)

        if email_harvest and not self._stopped():
            self._log("\nStarting Email Harvester...", "header")
            self._scan_emails(domain, result)
            current += 1
            self._progress(current, total)

        return result

    # ── WHOIS Lookup ─────────────────────────────────────────────────

    def _scan_whois(self, domain: str, result: ReconScanResult):
        """Perform WHOIS lookup using socket connection to whois servers."""
        self._log(f"  Querying WHOIS for {domain}...", "info")

        whois_data = self._query_whois(domain)
        if not whois_data:
            self._log("  WHOIS lookup failed or no data returned.", "warning")
            return

        result.whois_info = whois_data
        self._log("  WHOIS data retrieved successfully.", "success")

        # Parse key fields
        registrar = self._extract_whois_field(
            whois_data, ["Registrar:", "registrar:"],
        )
        creation = self._extract_whois_field(
            whois_data, ["Creation Date:", "created:", "Creation date:"],
        )
        expiry = self._extract_whois_field(
            whois_data, ["Registry Expiry Date:", "expires:", "Expiry date:"],
        )
        nameservers = self._extract_whois_list(
            whois_data, ["Name Server:", "nserver:", "name server:"],
        )

        # Report WHOIS info finding
        evidence_lines = []
        if registrar:
            evidence_lines.append(f"Registrar: {registrar}")
            self._log(f"  Registrar: {registrar}", "info")
        if creation:
            evidence_lines.append(f"Created: {creation}")
            self._log(f"  Created: {creation}", "info")
        if expiry:
            evidence_lines.append(f"Expires: {expiry}")
            self._log(f"  Expires: {expiry}", "info")
        if nameservers:
            ns_str = ", ".join(nameservers[:5])
            evidence_lines.append(f"Nameservers: {ns_str}")
            self._log(f"  Nameservers: {ns_str}", "info")

        finding = ReconFinding(
            scanner="whois",
            severity="Info",
            title=f"WHOIS Information for {domain}",
            description=(
                f"WHOIS data retrieved for {domain}. "
                "Review registration details for intelligence gathering."
            ),
            evidence="\n".join(evidence_lines) if evidence_lines else whois_data[:500],
            recommendation=(
                "Ensure domain registration details are appropriate. "
                "Consider using WHOIS privacy protection if personal "
                "information is exposed."
            ),
        )
        result.findings.append(finding)
        self._report(finding)

        # Check for privacy protection
        whois_lower = whois_data.lower()
        has_privacy = any(
            kw in whois_lower for kw in
            ["privacy", "redacted", "data protected", "whoisguard",
             "domains by proxy", "contact privacy"]
        )
        if not has_privacy and registrar:
            finding = ReconFinding(
                scanner="whois",
                severity="Low",
                title="No WHOIS Privacy Protection",
                description=(
                    "The domain does not appear to use WHOIS privacy "
                    "protection. Personal registration details may be "
                    "publicly visible."
                ),
                evidence=f"Registrar: {registrar}",
                recommendation=(
                    "Enable WHOIS privacy protection through your "
                    "domain registrar to hide personal information."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

    def _query_whois(self, domain: str) -> str:
        """Query WHOIS server for domain info."""
        # Determine WHOIS server based on TLD
        parts = domain.split(".")
        tld = parts[-1].lower()
        whois_servers = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "info": "whois.afilias.net",
            "io": "whois.nic.io",
            "co": "whois.nic.co",
            "me": "whois.nic.me",
            "us": "whois.nic.us",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "fr": "whois.nic.fr",
            "eu": "whois.eu",
            "ru": "whois.tcinet.ru",
            "au": "whois.auda.org.au",
            "ca": "whois.cira.ca",
            "nl": "whois.sidn.nl",
            "br": "whois.registro.br",
        }
        server = whois_servers.get(tld, "whois.iana.org")

        try:
            sock = socket.create_connection((server, 43), timeout=self.timeout)
            sock.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            sock.close()

            text = response.decode("utf-8", errors="replace")

            # If IANA redirects to another server, follow it
            if server == "whois.iana.org":
                refer_match = re.search(r"refer:\s*(\S+)", text)
                if refer_match:
                    real_server = refer_match.group(1)
                    try:
                        sock2 = socket.create_connection(
                            (real_server, 43), timeout=self.timeout,
                        )
                        sock2.sendall((domain + "\r\n").encode())
                        response2 = b""
                        while True:
                            data2 = sock2.recv(4096)
                            if not data2:
                                break
                            response2 += data2
                        sock2.close()
                        text = response2.decode("utf-8", errors="replace")
                    except Exception:
                        pass

            return text
        except Exception as e:
            self._log(f"  WHOIS query error: {e}", "error")
            return ""

    def _extract_whois_field(self, data: str, keys: list[str]) -> str:
        """Extract a single field from WHOIS data."""
        for key in keys:
            for line in data.splitlines():
                if key.lower() in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
        return ""

    def _extract_whois_list(self, data: str, keys: list[str]) -> list[str]:
        """Extract multiple values for a field from WHOIS data."""
        values = []
        for key in keys:
            for line in data.splitlines():
                if key.lower() in line.lower():
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        val = parts[1].strip()
                        if val and val not in values:
                            values.append(val)
        return values

    # ── DNS Reconnaissance ───────────────────────────────────────────

    def _scan_dns(self, domain: str, result: ReconScanResult):
        """Perform DNS reconnaissance."""
        records_found = 0

        # A records
        self._log("  Querying A records...", "info")
        try:
            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            seen = set()
            for info in ips:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    records_found += 1
                    self._log(f"    A: {ip}", "success")
            if seen:
                finding = ReconFinding(
                    scanner="dns",
                    severity="Info",
                    title=f"DNS A Records for {domain}",
                    description=f"Found {len(seen)} A record(s).",
                    evidence=", ".join(sorted(seen)),
                    recommendation="Review IP addresses for hosting information.",
                )
                result.findings.append(finding)
                self._report(finding)
        except socket.gaierror:
            self._log("    No A records found.", "warning")
        except Exception as e:
            self._log(f"    A record error: {e}", "error")

        if self._stopped():
            return

        # AAAA records (IPv6)
        self._log("  Querying AAAA records...", "info")
        try:
            ips6 = socket.getaddrinfo(domain, None, socket.AF_INET6)
            seen6 = set()
            for info in ips6:
                ip6 = info[4][0]
                if ip6 not in seen6:
                    seen6.add(ip6)
                    records_found += 1
                    self._log(f"    AAAA: {ip6}", "success")
            if seen6:
                finding = ReconFinding(
                    scanner="dns",
                    severity="Info",
                    title=f"DNS AAAA Records for {domain}",
                    description=f"Found {len(seen6)} AAAA record(s) (IPv6).",
                    evidence=", ".join(sorted(seen6)),
                    recommendation="IPv6 addresses found. Ensure IPv6 services are properly secured.",
                )
                result.findings.append(finding)
                self._report(finding)
        except socket.gaierror:
            self._log("    No AAAA records found.", "info")
        except Exception:
            pass

        if self._stopped():
            return

        # MX records via DNS query
        self._log("  Querying MX records...", "info")
        mx_records = self._dns_query(domain, "MX")
        if mx_records:
            records_found += len(mx_records)
            for mx in mx_records:
                self._log(f"    MX: {mx}", "success")
            finding = ReconFinding(
                scanner="dns",
                severity="Info",
                title=f"DNS MX Records for {domain}",
                description=f"Found {len(mx_records)} mail server(s).",
                evidence="\n".join(mx_records),
                recommendation="Review mail server configuration and SPF/DKIM/DMARC records.",
            )
            result.findings.append(finding)
            self._report(finding)
        else:
            self._log("    No MX records found.", "info")

        if self._stopped():
            return

        # NS records
        self._log("  Querying NS records...", "info")
        ns_records = self._dns_query(domain, "NS")
        if ns_records:
            records_found += len(ns_records)
            for ns in ns_records:
                self._log(f"    NS: {ns}", "success")
            finding = ReconFinding(
                scanner="dns",
                severity="Info",
                title=f"DNS NS Records for {domain}",
                description=f"Found {len(ns_records)} nameserver(s).",
                evidence="\n".join(ns_records),
                recommendation="Ensure nameservers are properly configured and secured.",
            )
            result.findings.append(finding)
            self._report(finding)
        else:
            self._log("    No NS records found.", "info")

        if self._stopped():
            return

        # TXT records (check for SPF, DKIM, DMARC)
        self._log("  Querying TXT records...", "info")
        txt_records = self._dns_query(domain, "TXT")
        if txt_records:
            records_found += len(txt_records)
            has_spf = False
            has_dmarc = False
            for txt in txt_records:
                self._log(f"    TXT: {txt[:80]}...", "success")
                if "v=spf1" in txt:
                    has_spf = True
                if "v=DMARC1" in txt:
                    has_dmarc = True

            finding = ReconFinding(
                scanner="dns",
                severity="Info",
                title=f"DNS TXT Records for {domain}",
                description=f"Found {len(txt_records)} TXT record(s).",
                evidence="\n".join(t[:200] for t in txt_records),
                recommendation="Review TXT records for security policies.",
            )
            result.findings.append(finding)
            self._report(finding)

            if not has_spf:
                finding = ReconFinding(
                    scanner="dns",
                    severity="Medium",
                    title="Missing SPF Record",
                    description=(
                        "No SPF (Sender Policy Framework) record found. "
                        "This makes the domain vulnerable to email spoofing."
                    ),
                    evidence="No TXT record containing 'v=spf1' found.",
                    recommendation=(
                        "Add an SPF record to prevent email spoofing. "
                        "Example: v=spf1 include:_spf.google.com ~all"
                    ),
                )
                result.findings.append(finding)
                self._report(finding)

            if not has_dmarc:
                # Also check _dmarc subdomain
                dmarc_records = self._dns_query(f"_dmarc.{domain}", "TXT")
                dmarc_found = any("v=DMARC1" in r for r in dmarc_records)
                if not dmarc_found:
                    finding = ReconFinding(
                        scanner="dns",
                        severity="Medium",
                        title="Missing DMARC Record",
                        description=(
                            "No DMARC record found. DMARC helps prevent "
                            "email spoofing and phishing attacks."
                        ),
                        evidence="No TXT record containing 'v=DMARC1' found.",
                        recommendation=(
                            "Add a DMARC record at _dmarc.{domain}. "
                            "Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)

        if self._stopped():
            return

        # Zone transfer attempt
        self._log("  Testing zone transfer (AXFR)...", "info")
        if ns_records:
            for ns in ns_records[:3]:
                ns_host = ns.strip().rstrip(".")
                if self._test_zone_transfer(domain, ns_host):
                    finding = ReconFinding(
                        scanner="dns",
                        severity="Critical",
                        title="DNS Zone Transfer Allowed!",
                        description=(
                            f"Nameserver {ns_host} allows zone transfers. "
                            "This exposes the entire DNS zone including "
                            "all subdomains and internal records."
                        ),
                        evidence=f"AXFR transfer successful from {ns_host}",
                        recommendation=(
                            "Restrict zone transfers to authorized secondary "
                            "nameservers only. Update named.conf or equivalent."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    break
            else:
                self._log("    Zone transfer denied (good).", "success")
        else:
            self._log("    No NS records to test zone transfer.", "info")

        result.dns_records_found = records_found
        self._log(
            f"\n  DNS recon complete. Found {records_found} records.",
            "success" if records_found > 0 else "info",
        )

    def _dns_query(self, domain: str, record_type: str) -> list[str]:
        """Perform DNS query using socket-based DNS resolution.

        For MX, NS, TXT records, we query public DNS over HTTPS (DoH).
        """
        # Use Google's DNS-over-HTTPS API for record types beyond A/AAAA
        url = (
            f"https://dns.google/resolve?"
            f"name={urllib.parse.quote(domain)}&type={record_type}"
        )

        try:
            status, body = self._make_request(url, timeout=5.0)
            if status != 200:
                return []

            import json
            data = json.loads(body)
            answers = data.get("Answer", [])
            results = []
            for ans in answers:
                rdata = ans.get("data", "")
                if rdata:
                    results.append(rdata)
            return results
        except Exception:
            return []

    def _test_zone_transfer(self, domain: str, ns: str) -> bool:
        """Attempt a DNS zone transfer (AXFR)."""
        try:
            # Build minimal AXFR query
            import struct
            # Transaction ID
            txid = b"\x00\x01"
            # Flags: standard query
            flags = b"\x00\x00"
            # Questions: 1, Answers: 0, Auth: 0, Additional: 0
            counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
            # Encode domain name
            qname = b""
            for label in domain.split("."):
                qname += bytes([len(label)]) + label.encode()
            qname += b"\x00"
            # Type AXFR (252), Class IN (1)
            qtype = b"\x00\xfc"
            qclass = b"\x00\x01"

            query = txid + flags + counts + qname + qtype + qclass
            # TCP DNS: prepend 2-byte length
            tcp_query = struct.pack("!H", len(query)) + query

            sock = socket.create_connection((ns, 53), timeout=5)
            sock.sendall(tcp_query)
            # Read response length
            resp_len_data = sock.recv(2)
            if len(resp_len_data) < 2:
                sock.close()
                return False
            resp_len = struct.unpack("!H", resp_len_data)[0]
            if resp_len > 0:
                resp = sock.recv(min(resp_len, 4096))
                sock.close()
                # Check if we got answer records (bytes 6-7 > 0)
                if len(resp) >= 8:
                    ancount = struct.unpack("!H", resp[6:8])[0]
                    return ancount > 0
            sock.close()
            return False
        except Exception:
            return False

    # ── Email Harvester ──────────────────────────────────────────────

    def _scan_emails(self, domain: str, result: ReconScanResult):
        """Harvest email addresses from website pages."""
        base_url = f"https://{domain}"
        all_emails: set[str] = set()

        self._log(
            f"  Scraping {len(self.EMAIL_SCRAPE_PATHS)} pages for emails...",
            "info",
        )

        for path in self.EMAIL_SCRAPE_PATHS:
            if self._stopped():
                break
            url = f"{base_url}{path}"
            status, body = self._make_request(url, timeout=5.0)
            if status in (200, 301, 302):
                # Extract emails from page content
                emails = set(re.findall(
                    self.EMAIL_PATTERNS[0], body, re.IGNORECASE,
                ))
                # Filter out common false positives
                filtered = set()
                for email in emails:
                    email_lower = email.lower()
                    if not any(
                        fp in email_lower for fp in
                        [".png", ".jpg", ".gif", ".css", ".js",
                         "example.com", "test.com", "sentry.io",
                         "webpack", "babel", "eslint"]
                    ):
                        filtered.add(email)
                if filtered:
                    new_emails = filtered - all_emails
                    for e in new_emails:
                        self._log(f"    Found: {e} (on {path})", "success")
                    all_emails.update(filtered)

        result.emails_found = len(all_emails)

        if all_emails:
            # Group by domain
            domain_emails: dict[str, list[str]] = {}
            for email in sorted(all_emails):
                e_domain = email.split("@")[1] if "@" in email else "unknown"
                domain_emails.setdefault(e_domain, []).append(email)

            for e_domain, emails in domain_emails.items():
                severity = "Info"
                if e_domain == domain:
                    severity = "Low"

                finding = ReconFinding(
                    scanner="email",
                    severity=severity,
                    title=f"Email Addresses Found ({e_domain})",
                    description=(
                        f"Found {len(emails)} email address(es) "
                        f"associated with {e_domain}."
                    ),
                    evidence="\n".join(emails),
                    recommendation=(
                        "Review exposed email addresses. They can be used "
                        "for phishing, social engineering, or credential "
                        "stuffing attacks. Consider using generic addresses "
                        "on public-facing pages."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)

            self._log(
                f"\n  Email harvest complete. Found {len(all_emails)} email(s).",
                "success",
            )
        else:
            self._log(
                "\n  No email addresses found on scanned pages.", "info",
            )
