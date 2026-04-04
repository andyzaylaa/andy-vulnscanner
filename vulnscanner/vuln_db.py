"""Vulnerability Database Updates for Andy VulnScanner.

Auto-update CVE database from NVD (National Vulnerability Database)
and local vulnerability definitions.
"""

import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional


@dataclass
class CVEEntry:
    """Represents a CVE entry."""

    cve_id: str
    description: str
    severity: str = "Unknown"
    cvss_score: float = 0.0
    published: str = ""
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)


class VulnDatabase:
    """Manage local vulnerability database with NVD updates."""

    DB_DIR = os.path.expanduser("~/.andy-vulnscanner")
    DB_FILE = os.path.join(DB_DIR, "vuln_db.json")
    META_FILE = os.path.join(DB_DIR, "db_meta.json")

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ):
        self.on_log = on_log
        self.on_progress = on_progress
        self._stop_event = threading.Event()
        self._db: dict[str, dict] = {}
        self._meta: dict = {}
        self._lock = threading.Lock()

        # Ensure DB directory exists
        os.makedirs(self.DB_DIR, exist_ok=True)
        self._load_db()

    def stop(self):
        self._stop_event.set()

    def reset(self):
        self._stop_event.clear()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── Database Management ──────────────────────────────────────────

    def get_db_info(self) -> dict:
        """Get database information."""
        with self._lock:
            return {
                "total_cves": len(self._db),
                "last_update": self._meta.get("last_update", "Never"),
                "db_version": self._meta.get("version", "1.0"),
                "db_size_kb": self._get_db_size(),
            }

    def _get_db_size(self) -> int:
        """Get database file size in KB."""
        try:
            if os.path.exists(self.DB_FILE):
                return os.path.getsize(self.DB_FILE) // 1024
        except Exception:
            pass
        return 0

    def search_cve(self, keyword: str) -> list[CVEEntry]:
        """Search CVE database by keyword."""
        results = []
        keyword_lower = keyword.lower()
        with self._lock:
            for cve_id, data in self._db.items():
                if (
                    keyword_lower in cve_id.lower()
                    or keyword_lower in data.get("description", "").lower()
                    or any(
                        keyword_lower in p.lower()
                        for p in data.get("affected_products", [])
                    )
                ):
                    results.append(self._dict_to_cve(cve_id, data))
        return results[:50]  # Limit results

    def lookup_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Look up a specific CVE."""
        with self._lock:
            data = self._db.get(cve_id.upper())
            if data:
                return self._dict_to_cve(cve_id.upper(), data)
        return None

    def _dict_to_cve(self, cve_id: str, data: dict) -> CVEEntry:
        """Convert dict to CVEEntry."""
        return CVEEntry(
            cve_id=cve_id,
            description=data.get("description", ""),
            severity=data.get("severity", "Unknown"),
            cvss_score=data.get("cvss_score", 0.0),
            published=data.get("published", ""),
            references=data.get("references", []),
            affected_products=data.get("affected_products", []),
        )

    # ── Update from NVD ──────────────────────────────────────────────

    def update(self, keywords: Optional[list[str]] = None) -> dict:
        """Update vulnerability database from NVD.

        Args:
            keywords: Optional list of keywords to search for
                     (e.g., ["apache", "nginx", "openssh"])

        Returns:
            Dict with update statistics.
        """
        self.reset()
        stats = {
            "new_cves": 0,
            "updated_cves": 0,
            "errors": 0,
            "total_fetched": 0,
        }

        self._log("Starting Vulnerability Database Update...", "header")
        self._log(f"  Database location: {self.DB_FILE}", "info")

        # Default keywords to search for common services
        if not keywords:
            keywords = [
                "apache", "nginx", "openssh", "mysql", "postgresql",
                "wordpress", "php", "python", "nodejs", "openssl",
            ]

        total = len(keywords)
        self._log(f"  Fetching CVEs for {total} keywords...", "info")

        for i, keyword in enumerate(keywords):
            if self._stopped():
                break

            self._log(f"\n  [{i + 1}/{total}] Searching: {keyword}...", "info")
            self._progress(i + 1, total)

            try:
                cves = self._fetch_nvd_cves(keyword)
                stats["total_fetched"] += len(cves)

                with self._lock:
                    for cve in cves:
                        cve_id = cve.get("id", "")
                        if not cve_id:
                            continue
                        if cve_id in self._db:
                            stats["updated_cves"] += 1
                        else:
                            stats["new_cves"] += 1

                        self._db[cve_id] = self._parse_nvd_cve(cve)

                self._log(
                    f"    Found {len(cves)} CVEs for '{keyword}'",
                    "success" if cves else "info",
                )

            except Exception as e:
                stats["errors"] += 1
                self._log(f"    Error fetching '{keyword}': {e}", "error")

            # Rate limiting (NVD API allows ~5 req/30s without key)
            if i < total - 1:
                time.sleep(6)

        # Save updated database
        self._meta["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._meta["version"] = "1.0"
        self._save_db()

        self._log("\n  Update complete:", "success")
        self._log(f"    New CVEs: {stats['new_cves']}", "info")
        self._log(f"    Updated: {stats['updated_cves']}", "info")
        self._log(f"    Total fetched: {stats['total_fetched']}", "info")
        self._log(f"    Total in DB: {len(self._db)}", "info")
        self._log(f"    Errors: {stats['errors']}", "info")

        return stats

    def _fetch_nvd_cves(self, keyword: str) -> list[dict]:
        """Fetch CVEs from NVD API for a keyword."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": 20,
        })
        url = f"{self.NVD_API_BASE}?{params}"

        hdrs = {
            "User-Agent": "AndyVulnScanner/1.0",
            "Accept": "application/json",
        }
        req = urllib.request.Request(url, headers=hdrs)

        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                vulnerabilities = data.get("vulnerabilities", [])
                return [v.get("cve", {}) for v in vulnerabilities]
        except urllib.error.HTTPError as e:
            if e.code == 403:
                self._log(
                    "    NVD rate limit reached. Waiting...", "warning",
                )
                time.sleep(30)
            raise
        except Exception:
            raise

    def _parse_nvd_cve(self, cve_data: dict) -> dict:
        """Parse NVD CVE response into our format."""
        # Get description
        descriptions = cve_data.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # Get CVSS score and severity
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        severity = "Unknown"

        # Try CVSS v3.1 first, then v3.0, then v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = metric_list[0].get(
                    "baseSeverity",
                    cvss_data.get("baseSeverity", "Unknown"),
                )
                break

        # Map severity
        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "NONE": "Info",
        }
        severity = severity_map.get(severity.upper(), severity)

        # Get references
        refs = []
        for ref in cve_data.get("references", [])[:5]:
            url = ref.get("url", "")
            if url:
                refs.append(url)

        # Get published date
        published = cve_data.get("published", "")[:10]

        # Get affected products from CPE
        affected = []
        configurations = cve_data.get("configurations", [])
        for config in configurations[:3]:
            nodes = config.get("nodes", [])
            for node in nodes[:3]:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches[:5]:
                    criteria = cpe.get("criteria", "")
                    # Extract product name from CPE string
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if product != "*":
                            affected.append(f"{vendor}/{product}")

        return {
            "description": desc[:500],
            "severity": severity,
            "cvss_score": cvss_score,
            "published": published,
            "references": refs,
            "affected_products": list(set(affected))[:10],
        }

    # ── Persistence ──────────────────────────────────────────────────

    def _save_db(self):
        """Save database to disk."""
        try:
            with open(self.DB_FILE, "w", encoding="utf-8") as f:
                json.dump(self._db, f)
            with open(self.META_FILE, "w", encoding="utf-8") as f:
                json.dump(self._meta, f, indent=2)
            self._log(
                f"  Database saved: {len(self._db)} CVEs "
                f"({self._get_db_size()} KB)", "success",
            )
        except Exception as e:
            self._log(f"  Error saving database: {e}", "error")

    def _load_db(self):
        """Load database from disk."""
        try:
            if os.path.exists(self.DB_FILE):
                with open(self.DB_FILE, encoding="utf-8") as f:
                    self._db = json.load(f)
            if os.path.exists(self.META_FILE):
                with open(self.META_FILE, encoding="utf-8") as f:
                    self._meta = json.load(f)
        except Exception:
            self._db = {}
            self._meta = {}

    # ── Built-in vulnerability definitions ───────────────────────────

    def seed_builtin_vulns(self):
        """Seed database with built-in common vulnerability definitions."""
        builtin = {
            "CVE-2021-44228": {
                "description": "Apache Log4j2 Remote Code Execution (Log4Shell). "
                "Allows RCE via JNDI lookup in log messages.",
                "severity": "Critical",
                "cvss_score": 10.0,
                "published": "2021-12-10",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "affected_products": ["apache/log4j"],
            },
            "CVE-2023-44487": {
                "description": "HTTP/2 Rapid Reset Attack (DDoS vulnerability) "
                "affecting multiple HTTP/2 implementations.",
                "severity": "High",
                "cvss_score": 7.5,
                "published": "2023-10-10",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
                "affected_products": ["apache/http_server", "nginx/nginx"],
            },
            "CVE-2024-3094": {
                "description": "XZ Utils backdoor. Malicious code in xz/liblzma "
                "versions 5.6.0 and 5.6.1.",
                "severity": "Critical",
                "cvss_score": 10.0,
                "published": "2024-03-29",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"],
                "affected_products": ["tukaani/xz"],
            },
            "CVE-2023-23397": {
                "description": "Microsoft Outlook Elevation of Privilege. "
                "Allows NTLM credential theft via crafted email.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2023-03-14",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-23397"],
                "affected_products": ["microsoft/outlook"],
            },
            "CVE-2021-34527": {
                "description": "PrintNightmare - Windows Print Spooler RCE. "
                "Allows remote code execution via print spooler.",
                "severity": "Critical",
                "cvss_score": 8.8,
                "published": "2021-07-02",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
                "affected_products": ["microsoft/windows"],
            },
            "CVE-2023-38408": {
                "description": "OpenSSH before 9.3p2 PKCS#11 provider RCE. "
                "Allows remote code execution via ssh-agent.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2023-07-20",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
                "affected_products": ["openssh/openssh"],
            },
            "CVE-2022-22965": {
                "description": "Spring4Shell - Spring Framework RCE via data binding.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2022-03-31",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
                "affected_products": ["vmware/spring_framework"],
            },
            "CVE-2021-26855": {
                "description": "Microsoft Exchange Server SSRF (ProxyLogon). "
                "Allows pre-auth RCE on Exchange servers.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2021-03-02",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
                "affected_products": ["microsoft/exchange_server"],
            },
            "CVE-2023-27997": {
                "description": "Fortinet FortiOS heap buffer overflow in SSL VPN. "
                "Pre-auth RCE vulnerability.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2023-06-12",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
                "affected_products": ["fortinet/fortios"],
            },
            "CVE-2023-4966": {
                "description": "Citrix Bleed - Citrix NetScaler ADC/Gateway "
                "information disclosure vulnerability.",
                "severity": "Critical",
                "cvss_score": 9.4,
                "published": "2023-10-10",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
                "affected_products": ["citrix/netscaler_adc"],
            },
        }

        new_count = 0
        with self._lock:
            for cve_id, data in builtin.items():
                if cve_id not in self._db:
                    self._db[cve_id] = data
                    new_count += 1

        if new_count > 0:
            self._save_db()
            self._log(f"  Seeded {new_count} built-in CVE definitions.", "success")

        return new_count
