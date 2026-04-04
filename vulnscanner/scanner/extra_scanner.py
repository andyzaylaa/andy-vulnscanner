"""Extra scanning modules for Andy VulnScanner.

Includes Subdomain Enumeration, Directory Brute Force,
and API Security scanners.
"""

import json
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
class ExtraFinding:
    """Represents a single extra scanner finding."""

    scanner: str  # "subdomain", "dirbrute", "api"
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class ExtraScanResult:
    """Result of an extra scan."""

    target: str
    findings: list[ExtraFinding] = field(default_factory=list)
    subdomains_found: int = 0
    directories_found: int = 0
    api_issues_found: int = 0
    scan_time: float = 0.0


class ExtraScanner:
    """Perform subdomain enumeration, directory brute force, and API scanning."""

    # ── Subdomain Wordlist ───────────────────────────────────────────

    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
        "ns1", "ns2", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
        "api", "dev", "staging", "stage", "test", "testing", "beta",
        "admin", "administrator", "portal", "vpn", "remote",
        "blog", "shop", "store", "forum", "wiki", "docs", "doc",
        "support", "help", "kb", "status", "monitor",
        "app", "apps", "mobile", "m", "cdn", "static", "assets",
        "media", "img", "images", "video", "download", "downloads",
        "git", "gitlab", "github", "svn", "repo", "ci", "jenkins",
        "jira", "confluence", "slack", "teams",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "elastic", "elasticsearch", "kibana", "grafana",
        "proxy", "gateway", "lb", "load", "balancer",
        "cloud", "aws", "azure", "gcp", "s3",
        "auth", "login", "sso", "oauth", "identity", "id",
        "secure", "security", "firewall", "waf",
        "backup", "bak", "old", "new", "temp", "tmp",
        "intranet", "internal", "corp", "corporate",
        "crm", "erp", "hr", "finance", "billing", "pay", "payment",
        "demo", "sandbox", "preview", "uat", "qa", "prod",
        "web", "web1", "web2", "server", "server1", "server2",
        "host", "node", "node1", "node2", "cluster",
        "search", "solr", "sphinx",
        "chat", "irc", "xmpp", "jabber",
        "cpanel", "whm", "plesk", "panel",
        "autodiscover", "autoconfig",
        "exchange", "owa", "outlook",
        "calendar", "cal", "contacts",
        "news", "feed", "rss",
        "analytics", "stats", "metrics", "logging",
        "vault", "secrets", "config",
    ]

    # ── Directory Brute Force Wordlist ────────────────────────────────

    DIR_WORDLIST = [
        # Admin / management
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/admin/login", "/admin/dashboard", "/admin/config",
        "/panel", "/cpanel", "/dashboard", "/manage", "/manager",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/phpmyadmin", "/phpmyadmin/", "/pma",
        # Config / sensitive files
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/.gitignore",
        "/.svn/entries", "/.svn/wc.db",
        "/.htaccess", "/.htpasswd",
        "/config.php", "/config.yml", "/config.json",
        "/configuration.php", "/settings.php", "/settings.py",
        "/wp-config.php", "/wp-config.php.bak",
        "/web.config", "/web.xml",
        "/.DS_Store", "/Thumbs.db",
        # Backup files
        "/backup", "/backup/", "/backups", "/backups/",
        "/db.sql", "/database.sql", "/dump.sql",
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/site.zip", "/www.zip", "/public.zip",
        # API endpoints
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
        "/api/docs", "/api/swagger", "/api/health",
        "/graphql", "/graphiql",
        "/swagger", "/swagger-ui", "/swagger-ui.html",
        "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml",
        "/api-docs", "/redoc",
        # Authentication
        "/login", "/signin", "/signup", "/register",
        "/logout", "/signout",
        "/forgot-password", "/reset-password",
        "/auth", "/oauth", "/sso",
        # Common directories
        "/uploads", "/upload", "/files", "/documents",
        "/static", "/assets", "/media", "/public",
        "/tmp", "/temp", "/cache", "/logs",
        "/debug", "/trace", "/test", "/tests",
        "/dev", "/development", "/staging",
        # Server info
        "/server-status", "/server-info",
        "/status", "/health", "/healthcheck", "/ping",
        "/info.php", "/phpinfo.php", "/info",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/security.txt", "/.well-known/security.txt",
        "/humans.txt", "/ads.txt",
        # Version control
        "/.hg/", "/.bzr/", "/CVS/Entries",
        # CI/CD
        "/.github/", "/.gitlab-ci.yml", "/Jenkinsfile",
        "/Dockerfile", "/docker-compose.yml",
        # Package files
        "/package.json", "/composer.json", "/Gemfile",
        "/requirements.txt", "/Pipfile", "/yarn.lock",
        "/package-lock.json", "/composer.lock",
        # Error / debug pages
        "/error", "/errors", "/404", "/500",
        "/elmah.axd", "/trace.axd",
        # CMS specific
        "/wp-content/", "/wp-includes/",
        "/wp-json/", "/wp-json/wp/v2/users",
        "/xmlrpc.php",
        "/joomla/", "/drupal/", "/magento/",
        "/cgi-bin/", "/cgi-bin/test-cgi",
        # Misc
        "/readme", "/readme.html", "/readme.txt",
        "/changelog", "/changelog.txt",
        "/license", "/license.txt",
        "/VERSION", "/RELEASE", "/INSTALL",
    ]

    # ── API Common Endpoints ─────────────────────────────────────────

    API_ENDPOINTS = [
        "/api", "/api/v1", "/api/v2",
        "/api/users", "/api/user", "/api/v1/users",
        "/api/admin", "/api/v1/admin",
        "/api/config", "/api/v1/config",
        "/api/health", "/api/status",
        "/api/debug", "/api/v1/debug",
        "/api/docs", "/api/swagger.json",
        "/api/graphql",
        "/api/login", "/api/auth", "/api/token",
        "/api/search", "/api/v1/search",
        "/api/upload", "/api/v1/upload",
        "/api/export", "/api/v1/export",
        "/api/internal", "/api/private",
    ]

    API_SENSITIVE_PATTERNS = [
        r'"password"', r'"secret"', r'"api_key"', r'"apikey"',
        r'"token"', r'"access_token"', r'"private_key"',
        r'"aws_access_key"', r'"aws_secret"',
        r'"database_url"', r'"db_password"',
        r'"smtp_password"', r'"mail_password"',
    ]

    def __init__(
        self,
        timeout: float = 5.0,
        threads: int = 10,
        on_finding: Optional[Callable[[ExtraFinding], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
    ):
        self.timeout = timeout
        self.threads = threads
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log
        self._stop_event = threading.Event()

    def stop(self):
        """Signal the scanner to stop."""
        self._stop_event.set()

    def reset(self):
        """Reset the scanner for a new scan."""
        self._stop_event.clear()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    def _report(self, finding: ExtraFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helper ──────────────────────────────────────────────────

    def _make_request(
        self, url: str, method: str = "GET",
        headers: Optional[dict] = None, timeout: Optional[float] = None,
    ) -> tuple[int, dict, str]:
        """Make an HTTP request and return (status, headers, body)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        hdrs = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
                "Gecko/20100101 Firefox/115.0 AndyVulnScanner/1.0"
            ),
        }
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, headers=hdrs, method=method)
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
        """Ensure URL has a scheme."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    # ── Main scan entry point ─────────────────────────────────────────

    def scan(
        self,
        target: str,
        subdomains: bool = True,
        dirbrute: bool = True,
        api_scan: bool = True,
    ) -> ExtraScanResult:
        """Run all selected extra scans against the target."""
        self.reset()
        url = self._normalize_url(target)
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        result = ExtraScanResult(target=domain)

        total = 0
        if subdomains:
            total += 1
        if dirbrute:
            total += 1
        if api_scan:
            total += 1
        current = 0

        # 1. Subdomain Enumeration
        if subdomains and not self._stopped():
            self._log("Starting Subdomain Enumeration...", "header")
            self._scan_subdomains(domain, result)
            current += 1
            self._progress(current, total)

        # 2. Directory Brute Force
        if dirbrute and not self._stopped():
            self._log("\nStarting Directory Brute Force...", "header")
            self._scan_directories(url, result)
            current += 1
            self._progress(current, total)

        # 3. API Security
        if api_scan and not self._stopped():
            self._log("\nStarting API Security Scan...", "header")
            self._scan_api(url, result)
            current += 1
            self._progress(current, total)

        return result

    # ── Subdomain Enumeration ────────────────────────────────────────

    def _scan_subdomains(self, domain: str, result: ExtraScanResult):
        """Enumerate subdomains via DNS resolution."""
        # Extract base domain (handle www.example.com -> example.com)
        parts = domain.split(".")
        if len(parts) > 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        self._log(f"  Base domain: {base_domain}", "info")
        self._log(
            f"  Testing {len(self.SUBDOMAIN_WORDLIST)} subdomains...", "info",
        )

        found_count = 0
        lock = threading.Lock()
        results_list: list[tuple[str, str]] = []

        def resolve_subdomain(sub: str):
            nonlocal found_count
            if self._stopped():
                return
            fqdn = f"{sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                with lock:
                    found_count += 1
                    results_list.append((fqdn, ip))
                    self._log(f"  FOUND: {fqdn} -> {ip}", "success")
            except socket.gaierror:
                pass
            except Exception:
                pass

        # Run in thread pool
        threads: list[threading.Thread] = []
        for sub in self.SUBDOMAIN_WORDLIST:
            if self._stopped():
                break
            t = threading.Thread(target=resolve_subdomain, args=(sub,))
            threads.append(t)
            t.start()
            # Limit concurrent threads
            if len(threads) >= self.threads:
                for t in threads:
                    t.join(timeout=self.timeout + 2)
                threads = []

        # Wait for remaining threads
        for t in threads:
            t.join(timeout=self.timeout + 2)

        result.subdomains_found = found_count

        # Create findings for discovered subdomains
        for fqdn, ip in results_list:
            severity = "Info"
            title = f"Subdomain Found: {fqdn}"
            desc = f"Resolved to {ip}"

            # Check for interesting subdomains
            sub_lower = fqdn.lower()
            if any(
                kw in sub_lower for kw in
                ["admin", "staging", "dev", "test", "debug", "internal"]
            ):
                severity = "Medium"
                desc += (
                    ". This appears to be a development/internal subdomain "
                    "that may expose sensitive functionality."
                )
            elif any(
                kw in sub_lower for kw in
                ["backup", "bak", "old", "temp", "tmp"]
            ):
                severity = "Medium"
                desc += (
                    ". This appears to be a backup/temporary subdomain "
                    "that may contain sensitive data."
                )
            elif any(
                kw in sub_lower for kw in
                ["db", "database", "mysql", "postgres", "redis", "mongo"]
            ):
                severity = "High"
                desc += (
                    ". This appears to be a database subdomain. "
                    "Exposed database interfaces are a critical risk."
                )
            elif any(
                kw in sub_lower for kw in
                ["vault", "secrets", "config"]
            ):
                severity = "High"
                desc += (
                    ". This subdomain may host configuration or secrets "
                    "management. Ensure it is not publicly accessible."
                )

            finding = ExtraFinding(
                scanner="subdomain",
                severity=severity,
                title=title,
                description=desc,
                evidence=f"{fqdn} -> {ip}",
                recommendation=(
                    "Review all discovered subdomains. Ensure development, "
                    "staging, and internal subdomains are not publicly "
                    "accessible. Remove DNS records for unused subdomains."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

        self._log(
            f"  Subdomain scan complete. Found {found_count} subdomains.",
            "success" if found_count > 0 else "info",
        )

    # ── Directory Brute Force ────────────────────────────────────────

    def _scan_directories(self, base_url: str, result: ExtraScanResult):
        """Brute force directories and files."""
        self._log(
            f"  Testing {len(self.DIR_WORDLIST)} paths...", "info",
        )

        found_count = 0
        lock = threading.Lock()
        tested = 0
        total_paths = len(self.DIR_WORDLIST)

        def check_path(path: str):
            nonlocal found_count, tested
            if self._stopped():
                return

            url = f"{base_url}{path}"
            status, resp_headers, body = self._make_request(url)

            with lock:
                tested += 1
                if tested % 30 == 0:
                    self._log(
                        f"  Progress: {tested}/{total_paths} paths tested...",
                        "info",
                    )

            if status == 0:
                return

            # Interesting status codes
            if status in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                severity = "Info"
                title = f"Found: {path} ({status})"
                desc = f"HTTP {status} response at {url}"

                # Classify severity based on what was found
                if status in (200, 204):
                    if any(
                        s in path.lower() for s in
                        [".env", ".git", "config", "backup", "dump",
                         ".htpasswd", ".htaccess", "wp-config",
                         "phpinfo", ".svn", "web.config"]
                    ):
                        severity = "Critical"
                        desc += (
                            ". SENSITIVE FILE EXPOSED! This file may "
                            "contain credentials, configuration data, "
                            "or source code."
                        )
                    elif any(
                        s in path.lower() for s in
                        ["admin", "dashboard", "manage", "panel",
                         "phpmyadmin", "cpanel"]
                    ):
                        severity = "High"
                        desc += (
                            ". Administrative interface accessible. "
                            "Ensure proper authentication is enforced."
                        )
                    elif any(
                        s in path.lower() for s in
                        ["swagger", "api-docs", "graphql", "graphiql",
                         "openapi", "redoc"]
                    ):
                        severity = "Medium"
                        desc += (
                            ". API documentation is publicly accessible. "
                            "This may reveal internal API structure."
                        )
                    elif any(
                        s in path.lower() for s in
                        ["debug", "trace", "test", "dev", "staging"]
                    ):
                        severity = "Medium"
                        desc += (
                            ". Development/debug endpoint accessible "
                            "in production."
                        )
                    elif any(
                        s in path.lower() for s in
                        ["upload", "uploads", "files", "documents"]
                    ):
                        severity = "Low"
                        desc += ". File upload or storage directory found."
                    else:
                        severity = "Info"
                        desc += ". Accessible endpoint found."

                elif status == 401:
                    severity = "Low"
                    desc += (
                        ". Authentication required. The endpoint exists "
                        "but requires credentials."
                    )
                elif status == 403:
                    severity = "Info"
                    desc += (
                        ". Access forbidden. The endpoint exists but "
                        "access is denied."
                    )
                elif status in (301, 302, 307, 308):
                    location = resp_headers.get("Location", "")
                    severity = "Info"
                    desc += f". Redirects to: {location[:200]}"

                # Detect content length for potential real pages
                content_len = len(body) if body else 0

                with lock:
                    found_count += 1

                finding = ExtraFinding(
                    scanner="dirbrute",
                    severity=severity,
                    title=title,
                    description=desc,
                    evidence=(
                        f"Status: {status}, Size: {content_len} bytes"
                    ),
                    recommendation=(
                        "Review all discovered paths. Remove or restrict "
                        "access to sensitive files and administrative "
                        "interfaces. Ensure proper authentication."
                    ),
                )

                with lock:
                    result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  [{status}] {path} ({content_len} bytes)",
                    "warning" if severity in ("Critical", "High")
                    else "success" if severity == "Medium"
                    else "info",
                )

        # Run in thread pool
        threads: list[threading.Thread] = []
        for path in self.DIR_WORDLIST:
            if self._stopped():
                break
            t = threading.Thread(target=check_path, args=(path,))
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join(timeout=self.timeout + 2)
                threads = []

        for t in threads:
            t.join(timeout=self.timeout + 2)

        result.directories_found = found_count
        self._log(
            f"  Directory scan complete. Found {found_count} paths "
            f"({tested} tested).",
            "success" if found_count > 0 else "info",
        )

    # ── API Security Scanner ─────────────────────────────────────────

    def _scan_api(self, base_url: str, result: ExtraScanResult):
        """Scan for API security issues."""
        issues = 0

        # 1. Discover API endpoints
        self._log("  Phase 1: Discovering API endpoints...", "info")
        live_endpoints: list[tuple[str, int, str]] = []

        for endpoint in self.API_ENDPOINTS:
            if self._stopped():
                break
            url = f"{base_url}{endpoint}"
            status, resp_headers, body = self._make_request(url)
            if status in (200, 201, 204, 401, 403, 405):
                live_endpoints.append((endpoint, status, body))
                self._log(
                    f"  API endpoint found: {endpoint} ({status})", "success",
                )

        self._log(
            f"  Found {len(live_endpoints)} live API endpoints.", "info",
        )

        # 2. Test each endpoint
        self._log("\n  Phase 2: Testing API security...", "info")

        for endpoint, status, body in live_endpoints:
            if self._stopped():
                break
            url = f"{base_url}{endpoint}"

            # Test: CORS on API endpoints
            self._test_api_cors(url, endpoint, result)

            # Test: Authentication requirements
            if status == 200:
                issues += self._test_api_auth(
                    url, endpoint, body, result,
                )

            # Test: Verbose error messages
            issues += self._test_api_errors(
                url, endpoint, result,
            )

            # Test: HTTP method testing
            issues += self._test_api_methods(
                url, endpoint, result,
            )

            # Test: Information disclosure in response
            issues += self._test_api_disclosure(
                url, endpoint, body, result,
            )

        # 3. Check for rate limiting on discovered endpoints
        if live_endpoints and not self._stopped():
            self._log("\n  Phase 3: Testing rate limiting...", "info")
            first_ep = live_endpoints[0]
            issues += self._test_rate_limit(
                f"{base_url}{first_ep[0]}", first_ep[0], result,
            )

        result.api_issues_found = issues
        self._log(
            f"  API scan complete. Found {issues} issues across "
            f"{len(live_endpoints)} endpoints.",
            "warning" if issues > 0 else "info",
        )

    def _test_api_cors(
        self, url: str, endpoint: str, result: ExtraScanResult,
    ):
        """Test CORS configuration on API endpoint."""
        headers = {"Origin": "https://evil.com"}
        status, resp_headers, _ = self._make_request(
            url, headers=headers,
        )
        if status == 0:
            return

        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            finding = ExtraFinding(
                scanner="api",
                severity="High",
                title=f"API CORS Misconfigured: {endpoint}",
                description=(
                    f"API endpoint {endpoint} allows requests from "
                    f"any origin (ACAO: {acao}). This could allow "
                    f"unauthorized cross-origin access to API data."
                ),
                evidence=f"ACAO: {acao}",
                recommendation=(
                    "Restrict CORS to trusted origins only. "
                    "API endpoints should never use wildcard origins."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

    def _test_api_auth(
        self, url: str, endpoint: str, body: str,
        result: ExtraScanResult,
    ) -> int:
        """Test if API endpoints require authentication."""
        issues = 0

        # Check if sensitive endpoints are accessible without auth
        sensitive_patterns = [
            "user", "admin", "config", "debug", "internal",
            "private", "export", "upload",
        ]
        is_sensitive = any(p in endpoint.lower() for p in sensitive_patterns)

        if is_sensitive and body:
            # Check if the response contains actual data
            try:
                data = json.loads(body)
                if isinstance(data, (list, dict)) and data:
                    finding = ExtraFinding(
                        scanner="api",
                        severity="High",
                        title=f"Unauthenticated API Access: {endpoint}",
                        description=(
                            f"Sensitive API endpoint {endpoint} returns data "
                            f"without requiring authentication. "
                            f"Response contains "
                            f"{type(data).__name__} data."
                        ),
                        evidence=f"Status: 200, Response type: {type(data).__name__}",
                        recommendation=(
                            "Require authentication for all sensitive API "
                            "endpoints. Use API keys, OAuth tokens, or "
                            "session-based authentication."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    issues += 1
                    self._log(
                        f"  FOUND: Unauthenticated access to {endpoint}",
                        "error",
                    )
            except (json.JSONDecodeError, ValueError):
                pass

        return issues

    def _test_api_errors(
        self, url: str, endpoint: str, result: ExtraScanResult,
    ) -> int:
        """Test for verbose error messages."""
        issues = 0

        # Send a malformed request to trigger errors
        test_url = f"{url}/../../etc/passwd"
        status, _, body = self._make_request(test_url)

        if status >= 400 and body:
            error_patterns = [
                (r"(?:stack\s*trace|traceback)", "Stack Trace Exposed"),
                (r"(?:Exception\s+in|at\s+\w+\.\w+\.\w+)", "Exception Details"),
                (r"(?:syntax\s+error|parse\s+error)", "Syntax Error Exposed"),
                (r"(?:/var/www/|/home/|/opt/|C:\\)", "Server Path Exposed"),
                (r"(?:mysql|postgres|sqlite|oracle)", "Database Info Exposed"),
            ]

            for pattern, title in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    finding = ExtraFinding(
                        scanner="api",
                        severity="Medium",
                        title=f"{title}: {endpoint}",
                        description=(
                            f"API endpoint {endpoint} exposes detailed "
                            f"error information that could help attackers "
                            f"understand the application's internals."
                        ),
                        evidence=f"Pattern matched: {title}",
                        recommendation=(
                            "Return generic error messages in production. "
                            "Log detailed errors server-side only. "
                            "Never expose stack traces or file paths."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    issues += 1
                    self._log(
                        f"  FOUND: {title} at {endpoint}", "warning",
                    )
                    break

        return issues

    def _test_api_methods(
        self, url: str, endpoint: str, result: ExtraScanResult,
    ) -> int:
        """Test which HTTP methods are allowed."""
        issues = 0
        dangerous_methods = ["DELETE", "PUT", "PATCH"]

        for method in dangerous_methods:
            if self._stopped():
                break
            status, _, _ = self._make_request(url, method=method)
            if status in (200, 201, 204, 202):
                finding = ExtraFinding(
                    scanner="api",
                    severity="Medium",
                    title=f"Dangerous HTTP Method Allowed: {method} {endpoint}",
                    description=(
                        f"API endpoint {endpoint} accepts {method} requests "
                        f"(status {status}). This could allow unauthorized "
                        f"data modification or deletion."
                    ),
                    evidence=f"Method: {method}, Status: {status}",
                    recommendation=(
                        f"Restrict {method} method to authenticated and "
                        f"authorized users only. Return 405 Method Not "
                        f"Allowed for unsupported methods."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                issues += 1
                self._log(
                    f"  FOUND: {method} allowed on {endpoint} ({status})",
                    "warning",
                )

        return issues

    def _test_api_disclosure(
        self, url: str, endpoint: str, body: str,
        result: ExtraScanResult,
    ) -> int:
        """Check API responses for sensitive information disclosure."""
        issues = 0
        if not body:
            return 0

        for pattern in self.API_SENSITIVE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                finding = ExtraFinding(
                    scanner="api",
                    severity="High",
                    title=f"Sensitive Data in Response: {endpoint}",
                    description=(
                        f"API endpoint {endpoint} response contains "
                        f"what appears to be sensitive data "
                        f"(matched: {pattern.strip('r')}). "
                        f"This could expose credentials or secrets."
                    ),
                    evidence=f"Pattern found: {pattern}",
                    recommendation=(
                        "Never include sensitive data like passwords, "
                        "API keys, or tokens in API responses. "
                        "Use data masking and response filtering."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                issues += 1
                self._log(
                    f"  FOUND: Sensitive data pattern in {endpoint}",
                    "error",
                )
                break

        return issues

    def _test_rate_limit(
        self, url: str, endpoint: str, result: ExtraScanResult,
    ) -> int:
        """Test if API has rate limiting."""
        issues = 0
        success_count = 0
        test_count = 20

        for i in range(test_count):
            if self._stopped():
                break
            status, resp_headers, _ = self._make_request(
                url, timeout=3.0,
            )
            if status in (200, 201, 204):
                success_count += 1
            elif status == 429:
                self._log(
                    f"  Rate limiting detected after {i + 1} requests.",
                    "success",
                )
                return 0

            # Check for rate limit headers
            if any(
                h.lower().startswith("x-ratelimit")
                for h in resp_headers
            ):
                self._log(
                    "  Rate limit headers detected.", "success",
                )
                return 0

        if success_count == test_count:
            finding = ExtraFinding(
                scanner="api",
                severity="Medium",
                title=f"No Rate Limiting: {endpoint}",
                description=(
                    f"API endpoint {endpoint} does not appear to have "
                    f"rate limiting. All {test_count} rapid requests "
                    f"succeeded. This could allow brute force attacks "
                    f"or API abuse."
                ),
                evidence=f"{success_count}/{test_count} requests succeeded",
                recommendation=(
                    "Implement rate limiting on all API endpoints. "
                    "Use tools like Redis-based rate limiters or "
                    "API gateways with built-in rate limiting."
                ),
            )
            result.findings.append(finding)
            self._report(finding)
            issues += 1
            self._log(
                f"  WARNING: No rate limiting detected on {endpoint}",
                "warning",
            )

        return issues
