"""WAF Detection & CMS Vulnerability Scanner for Andy VulnScanner.

Detects Web Application Firewalls and scans for CMS-specific
vulnerabilities in WordPress, Joomla, and Drupal.
"""

import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class WafCmsFinding:
    """Represents a WAF/CMS finding."""

    scanner: str  # "waf", "cms"
    severity: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class WafCmsResult:
    """Result of WAF/CMS scan."""

    target: str
    findings: list[WafCmsFinding] = field(default_factory=list)
    waf_detected: str = ""
    cms_detected: str = ""
    cms_version: str = ""
    scan_time: float = 0.0


class WafCmsScanner:
    """Detect WAFs and scan for CMS vulnerabilities."""

    # WAF signatures: (header_or_body_pattern, waf_name)
    WAF_SIGNATURES = [
        # Header-based detection
        ("cloudflare", "Cloudflare"),
        ("cf-ray", "Cloudflare"),
        ("akamai", "Akamai"),
        ("x-sucuri", "Sucuri"),
        ("sucuri", "Sucuri"),
        ("x-cdn", "Incapsula/Imperva"),
        ("incapsula", "Incapsula/Imperva"),
        ("imperva", "Incapsula/Imperva"),
        ("barracuda", "Barracuda WAF"),
        ("f5-trafficshield", "F5 BIG-IP"),
        ("bigipserver", "F5 BIG-IP"),
        ("x-webknight", "WebKnight"),
        ("x-powered-by-anquanbao", "Anquanbao WAF"),
        ("x-protected-by", "Generic WAF"),
        ("x-waf", "Generic WAF"),
        ("mod_security", "ModSecurity"),
        ("modsecurity", "ModSecurity"),
        ("aws-waf", "AWS WAF"),
        ("x-amz-cf", "AWS CloudFront"),
        ("x-azure-ref", "Azure Front Door"),
        ("ddos-guard", "DDoS-Guard"),
        ("stackpath", "StackPath"),
        ("x-firewall", "Generic Firewall"),
        ("wordfence", "Wordfence (WordPress)"),
    ]

    # WAF detection payloads (should trigger WAF blocks)
    WAF_TEST_PAYLOADS = [
        "/<script>alert(1)</script>",
        "/?id=1' OR 1=1--",
        "/etc/passwd",
        "/?cmd=cat+/etc/passwd",
        "/?file=../../etc/passwd",
    ]

    # CMS detection paths
    CMS_PATHS = {
        "WordPress": [
            ("/wp-login.php", "wp-login"),
            ("/wp-admin/", "wp-admin"),
            ("/wp-content/", "wp-content"),
            ("/wp-includes/", "wp-includes"),
            ("/xmlrpc.php", "xmlrpc"),
            ("/wp-json/", "wp-json"),
        ],
        "Joomla": [
            ("/administrator/", "Joomla"),
            ("/components/", "com_"),
            ("/modules/", "Joomla"),
            ("/media/system/", "Joomla"),
        ],
        "Drupal": [
            ("/core/misc/drupal.js", "Drupal"),
            ("/misc/drupal.js", "Drupal"),
            ("/sites/default/", "Drupal"),
            ("/core/CHANGELOG.txt", "Drupal"),
        ],
    }

    # WordPress vulnerable paths
    WP_VULN_CHECKS = [
        ("/wp-json/wp/v2/users", "WordPress User Enumeration",
         "The REST API exposes user information including usernames.",
         "High"),
        ("/xmlrpc.php", "WordPress XML-RPC Enabled",
         "XML-RPC is enabled, which can be used for brute force and DDoS amplification.",
         "Medium"),
        ("/?author=1", "WordPress Author Enumeration",
         "Author enumeration via URL parameter is possible.",
         "Low"),
        ("/wp-config.php.bak", "WordPress Config Backup",
         "A backup of wp-config.php was found, exposing database credentials.",
         "Critical"),
        ("/wp-content/debug.log", "WordPress Debug Log Exposed",
         "Debug log file is publicly accessible, may contain sensitive information.",
         "High"),
        ("/readme.html", "WordPress Readme File",
         "The readme.html file reveals the WordPress version.",
         "Low"),
        ("/wp-content/uploads/", "WordPress Uploads Directory Listing",
         "Uploads directory listing is enabled, exposing uploaded files.",
         "Medium"),
        ("/wp-cron.php", "WordPress WP-Cron Accessible",
         "WP-Cron is publicly accessible, can be abused for DDoS.",
         "Low"),
    ]

    def __init__(
        self,
        timeout: float = 5.0,
        on_finding: Optional[Callable[[WafCmsFinding], None]] = None,
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

    def _report(self, finding: WafCmsFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helper ──────────────────────────────────────────────────

    def _make_request(
        self, url: str, timeout: Optional[float] = None,
    ) -> tuple[int, dict, str]:
        """Make an HTTP request and return (status, headers, body)."""
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
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, dict(e.headers), body
        except Exception:
            return 0, {}, ""

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    # ── Main scan entry point ────────────────────────────────────────

    def scan(
        self,
        target: str,
        waf_detect: bool = True,
        cms_scan: bool = True,
    ) -> WafCmsResult:
        """Run WAF detection and CMS scanning."""
        self.reset()
        url = self._normalize_url(target)
        result = WafCmsResult(target=url)
        start_time = time.time()

        total = sum([waf_detect, cms_scan])
        current = 0

        if waf_detect and not self._stopped():
            self._log("Starting WAF Detection...", "header")
            self._detect_waf(url, result)
            current += 1
            self._progress(current, total)

        if cms_scan and not self._stopped():
            self._log("\nStarting CMS Vulnerability Scanner...", "header")
            self._scan_cms(url, result)
            current += 1
            self._progress(current, total)

        result.scan_time = time.time() - start_time
        return result

    # ── WAF Detection ────────────────────────────────────────────────

    def _detect_waf(self, base_url: str, result: WafCmsResult):
        """Detect Web Application Firewall."""
        detected_wafs: set[str] = set()

        # Phase 1: Check response headers for WAF signatures
        self._log("  Phase 1: Checking response headers...", "info")
        status, headers, body = self._make_request(base_url)
        if status == 0:
            self._log("  Target not reachable.", "error")
            return

        # Check all headers and their values
        for header_name, header_value in headers.items():
            combined = f"{header_name}: {header_value}".lower()
            for pattern, waf_name in self.WAF_SIGNATURES:
                if pattern in combined:
                    detected_wafs.add(waf_name)

        # Check body/cookies too
        all_text = (body + str(headers)).lower()
        for pattern, waf_name in self.WAF_SIGNATURES:
            if pattern in all_text:
                detected_wafs.add(waf_name)

        if detected_wafs:
            for waf in detected_wafs:
                self._log(f"  WAF Detected: {waf}", "success")

        if self._stopped():
            return

        # Phase 2: Send malicious payloads to trigger WAF
        self._log("  Phase 2: Testing WAF with trigger payloads...", "info")
        blocked_count = 0

        for payload in self.WAF_TEST_PAYLOADS:
            if self._stopped():
                break
            test_url = f"{base_url}{payload}"
            status, resp_headers, resp_body = self._make_request(test_url)

            # WAF typically responds with 403, 406, 429, or custom pages
            is_blocked = False
            if status in (403, 406, 429, 503):
                is_blocked = True
            elif status != 0:
                lower_body = resp_body.lower()
                block_indicators = [
                    "blocked", "forbidden", "access denied",
                    "security", "waf", "firewall", "not acceptable",
                    "request blocked", "web application firewall",
                ]
                if any(ind in lower_body for ind in block_indicators):
                    is_blocked = True

            if is_blocked:
                blocked_count += 1
                # Check for new WAF signatures in response
                for header_name, header_value in resp_headers.items():
                    combined = f"{header_name}: {header_value}".lower()
                    for pattern, waf_name in self.WAF_SIGNATURES:
                        if pattern in combined:
                            detected_wafs.add(waf_name)

        self._log(
            f"  {blocked_count}/{len(self.WAF_TEST_PAYLOADS)} payloads blocked.",
            "info",
        )

        # Report findings
        if detected_wafs:
            waf_list = ", ".join(sorted(detected_wafs))
            result.waf_detected = waf_list

            finding = WafCmsFinding(
                scanner="waf",
                severity="Info",
                title=f"WAF Detected: {waf_list}",
                description=(
                    f"Web Application Firewall(s) detected: {waf_list}. "
                    f"{blocked_count}/{len(self.WAF_TEST_PAYLOADS)} "
                    f"test payloads were blocked."
                ),
                evidence=(
                    f"WAFs: {waf_list}\n"
                    f"Blocked payloads: {blocked_count}/{len(self.WAF_TEST_PAYLOADS)}"
                ),
                recommendation=(
                    "WAF is present, which is good for defense. However, "
                    "WAFs can often be bypassed. Ensure application-level "
                    "security is also in place."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

            if blocked_count < len(self.WAF_TEST_PAYLOADS):
                finding = WafCmsFinding(
                    scanner="waf",
                    severity="Medium",
                    title="WAF Not Blocking All Payloads",
                    description=(
                        f"WAF only blocked {blocked_count} out of "
                        f"{len(self.WAF_TEST_PAYLOADS)} test payloads. "
                        "Some attacks may bypass the WAF."
                    ),
                    evidence=f"Blocked: {blocked_count}/{len(self.WAF_TEST_PAYLOADS)}",
                    recommendation=(
                        "Review WAF rules and ensure all common attack "
                        "patterns are covered. Consider enabling strict mode."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
        else:
            if blocked_count > 0:
                finding = WafCmsFinding(
                    scanner="waf",
                    severity="Info",
                    title="Possible WAF Detected (Unidentified)",
                    description=(
                        f"Some payloads were blocked ({blocked_count}/"
                        f"{len(self.WAF_TEST_PAYLOADS)}) but no specific "
                        "WAF was identified."
                    ),
                    evidence=f"Blocked payloads: {blocked_count}",
                    recommendation="Investigate the blocking mechanism.",
                )
                result.findings.append(finding)
                self._report(finding)
            else:
                finding = WafCmsFinding(
                    scanner="waf",
                    severity="Medium",
                    title="No WAF Detected",
                    description=(
                        "No Web Application Firewall was detected. "
                        "The application may be directly exposed to attacks."
                    ),
                    evidence="No WAF signatures found, no payloads blocked.",
                    recommendation=(
                        "Consider deploying a WAF (e.g., Cloudflare, "
                        "ModSecurity, AWS WAF) to protect against common "
                        "web attacks like SQLi, XSS, and DDoS."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)

        self._log("  WAF detection complete.", "success")

    # ── CMS Scanner ──────────────────────────────────────────────────

    def _scan_cms(self, base_url: str, result: WafCmsResult):
        """Detect and scan CMS for vulnerabilities."""
        # Phase 1: Detect CMS
        self._log("  Phase 1: Detecting CMS...", "info")
        cms_type = self._detect_cms(base_url)

        if not cms_type:
            self._log("  No known CMS detected.", "info")
            finding = WafCmsFinding(
                scanner="cms",
                severity="Info",
                title="No CMS Detected",
                description=(
                    "No WordPress, Joomla, or Drupal installation was "
                    "detected. The site may use a custom framework."
                ),
                recommendation="Manual review recommended if CMS is suspected.",
            )
            result.findings.append(finding)
            self._report(finding)
            return

        result.cms_detected = cms_type
        self._log(f"  CMS Detected: {cms_type}", "success")

        finding = WafCmsFinding(
            scanner="cms",
            severity="Info",
            title=f"CMS Detected: {cms_type}",
            description=f"{cms_type} installation detected.",
            evidence=f"CMS: {cms_type}",
            recommendation=f"Ensure {cms_type} is updated to the latest version.",
        )
        result.findings.append(finding)
        self._report(finding)

        if self._stopped():
            return

        # Phase 2: CMS-specific vulnerability checks
        self._log("  Phase 2: Checking for CMS vulnerabilities...", "info")

        if cms_type == "WordPress":
            self._scan_wordpress(base_url, result)
        elif cms_type == "Joomla":
            self._scan_joomla(base_url, result)
        elif cms_type == "Drupal":
            self._scan_drupal(base_url, result)

        self._log("  CMS scan complete.", "success")

    def _detect_cms(self, base_url: str) -> str:
        """Detect which CMS is running."""
        # Check response body for CMS indicators
        status, headers, body = self._make_request(base_url)
        if status == 0:
            return ""

        lower_body = body.lower()

        # Quick detection from meta tags and body
        if "wp-content" in lower_body or "wordpress" in lower_body:
            return "WordPress"
        if "joomla" in lower_body:
            return "Joomla"
        if "drupal" in lower_body:
            return "Drupal"

        # Check generator meta tag
        gen_match = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
            body, re.IGNORECASE,
        )
        if gen_match:
            gen = gen_match.group(1).lower()
            if "wordpress" in gen:
                return "WordPress"
            if "joomla" in gen:
                return "Joomla"
            if "drupal" in gen:
                return "Drupal"

        # Check CMS-specific paths
        for cms_name, paths in self.CMS_PATHS.items():
            for path, indicator in paths:
                if self._stopped():
                    return ""
                check_url = f"{base_url}{path}"
                s, _, b = self._make_request(check_url)
                if s in (200, 301, 302) and indicator.lower() in b.lower():
                    return cms_name

        return ""

    def _scan_wordpress(self, base_url: str, result: WafCmsResult):
        """Scan WordPress for vulnerabilities."""
        for path, title, desc, severity in self.WP_VULN_CHECKS:
            if self._stopped():
                break
            url = f"{base_url}{path}"
            status, headers, body = self._make_request(url)

            is_vuln = False
            evidence = f"URL: {url}\nStatus: {status}"

            if path == "/wp-json/wp/v2/users" and status == 200:
                try:
                    import json
                    users = json.loads(body)
                    if isinstance(users, list) and users:
                        usernames = [u.get("slug", "") for u in users[:5]]
                        evidence += f"\nUsers found: {', '.join(usernames)}"
                        is_vuln = True
                except Exception:
                    pass

            elif path == "/xmlrpc.php" and status == 200:
                if "xml-rpc" in body.lower() or "xmlrpc" in body.lower():
                    is_vuln = True

            elif path == "/?author=1" and status in (200, 301, 302):
                if "author" in str(headers.get("Location", "")).lower():
                    is_vuln = True
                elif re.search(r"author/[\w-]+", body):
                    is_vuln = True

            elif path in ("/wp-config.php.bak", "/wp-content/debug.log"):
                if status == 200 and len(body) > 50:
                    is_vuln = True

            elif path == "/readme.html" and status == 200:
                if "wordpress" in body.lower():
                    version_match = re.search(
                        r"Version\s+([\d.]+)", body,
                    )
                    if version_match:
                        result.cms_version = version_match.group(1)
                        evidence += f"\nVersion: {result.cms_version}"
                    is_vuln = True

            elif path == "/wp-content/uploads/" and status == 200:
                if "<title>index of" in body.lower() or "parent directory" in body.lower():
                    is_vuln = True

            elif path == "/wp-cron.php" and status == 200:
                is_vuln = True

            if is_vuln:
                self._log(f"  VULN: {title}", "error")
                finding = WafCmsFinding(
                    scanner="cms",
                    severity=severity,
                    title=title,
                    description=desc,
                    evidence=evidence,
                    recommendation=self._wp_recommendation(path),
                )
                result.findings.append(finding)
                self._report(finding)

        # Check for WordPress version in meta
        status, _, body = self._make_request(base_url)
        if status == 200:
            ver_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)',
                body, re.IGNORECASE,
            )
            if ver_match and not result.cms_version:
                result.cms_version = ver_match.group(1)
                self._log(f"  WordPress version: {result.cms_version}", "info")

    def _wp_recommendation(self, path: str) -> str:
        """Get WordPress-specific recommendation."""
        recommendations = {
            "/wp-json/wp/v2/users": (
                "Disable REST API user enumeration. Add to functions.php:\n"
                "add_filter('rest_endpoints', function($endpoints) {\n"
                "  unset($endpoints['/wp/v2/users']);\n"
                "  return $endpoints;\n"
                "});"
            ),
            "/xmlrpc.php": (
                "Disable XML-RPC by adding to .htaccess:\n"
                "<Files xmlrpc.php>\n"
                "  Order Deny,Allow\n"
                "  Deny from all\n"
                "</Files>"
            ),
            "/?author=1": "Disable author archives or use a security plugin.",
            "/wp-config.php.bak": "Remove all backup files from the web root immediately!",
            "/wp-content/debug.log": (
                "Delete debug.log and disable WP_DEBUG_LOG in wp-config.php."
            ),
            "/readme.html": "Delete readme.html from the WordPress root.",
            "/wp-content/uploads/": (
                "Disable directory listing. Add 'Options -Indexes' to .htaccess."
            ),
            "/wp-cron.php": (
                "Disable WP-Cron and use system cron instead:\n"
                "Add to wp-config.php: define('DISABLE_WP_CRON', true);\n"
                "Add system cron: */15 * * * * curl -s {url}/wp-cron.php"
            ),
        }
        return recommendations.get(path, "Review and fix the identified issue.")

    def _scan_joomla(self, base_url: str, result: WafCmsResult):
        """Scan Joomla for vulnerabilities."""
        joomla_checks = [
            ("/administrator/manifests/files/joomla.xml", "Joomla Version Disclosure",
             "Joomla version information is publicly accessible.", "Low"),
            ("/configuration.php.bak", "Joomla Config Backup",
             "A backup of the configuration file was found.", "Critical"),
            ("/administrator/", "Joomla Admin Panel Accessible",
             "The Joomla administrator panel is publicly accessible.", "Low"),
        ]

        for path, title, desc, severity in joomla_checks:
            if self._stopped():
                break
            url = f"{base_url}{path}"
            status, _, body = self._make_request(url)

            if status == 200 and len(body) > 50:
                self._log(f"  VULN: {title}", "error")

                evidence = f"URL: {url}\nStatus: {status}"
                if "version" in path.lower():
                    ver_match = re.search(r"<version>([\d.]+)</version>", body)
                    if ver_match:
                        result.cms_version = ver_match.group(1)
                        evidence += f"\nVersion: {result.cms_version}"

                finding = WafCmsFinding(
                    scanner="cms",
                    severity=severity,
                    title=title,
                    description=desc,
                    evidence=evidence,
                    recommendation="Restrict access and remove sensitive files.",
                )
                result.findings.append(finding)
                self._report(finding)

    def _scan_drupal(self, base_url: str, result: WafCmsResult):
        """Scan Drupal for vulnerabilities."""
        drupal_checks = [
            ("/CHANGELOG.txt", "Drupal Version Disclosure",
             "Drupal changelog is publicly accessible, revealing version.", "Low"),
            ("/core/CHANGELOG.txt", "Drupal Core Version Disclosure",
             "Drupal core changelog reveals version information.", "Low"),
            ("/user/register", "Drupal User Registration Open",
             "User registration page is publicly accessible.", "Medium"),
            ("/admin/config", "Drupal Admin Config Accessible",
             "Drupal admin configuration may be accessible.", "High"),
        ]

        for path, title, desc, severity in drupal_checks:
            if self._stopped():
                break
            url = f"{base_url}{path}"
            status, _, body = self._make_request(url)

            if status == 200 and "drupal" in body.lower():
                self._log(f"  VULN: {title}", "error")

                evidence = f"URL: {url}"
                if "changelog" in path.lower():
                    ver_match = re.search(r"Drupal\s+([\d.]+)", body)
                    if ver_match:
                        result.cms_version = ver_match.group(1)
                        evidence += f"\nVersion: {result.cms_version}"

                finding = WafCmsFinding(
                    scanner="cms",
                    severity=severity,
                    title=title,
                    description=desc,
                    evidence=evidence,
                    recommendation="Restrict access and update Drupal.",
                )
                result.findings.append(finding)
                self._report(finding)
