"""Website vulnerability scanning module for Andy VulnScanner."""

import re
import socket
import ssl
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse


@dataclass
class WebFinding:
    """Represents a single web scanning finding."""

    category: str  # "header", "ssl", "info", "directory", "technology"
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    recommendation: str = ""
    detail: str = ""


@dataclass
class WebScanResult:
    """Result of a complete website scan."""

    url: str
    ip_address: str = ""
    status_code: int = 0
    server: str = ""
    headers: dict = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    findings: list[WebFinding] = field(default_factory=list)
    directories_found: list[str] = field(default_factory=list)
    ssl_info: dict = field(default_factory=dict)
    scan_time: float = 0.0


class WebScanner:
    """Scan websites for common vulnerabilities and misconfigurations."""

    # Common directories to check
    COMMON_DIRS = [
        "/admin", "/login", "/wp-admin", "/wp-login.php",
        "/administrator", "/phpmyadmin", "/cpanel",
        "/robots.txt", "/sitemap.xml", "/.env",
        "/.git/config", "/.htaccess", "/backup",
        "/api", "/api/v1", "/swagger", "/docs",
        "/config", "/console", "/debug", "/info",
        "/server-status", "/server-info",
        "/wp-content", "/wp-includes",
        "/.well-known/security.txt", "/security.txt",
        "/xmlrpc.php", "/readme.html",
        "/test", "/temp", "/tmp", "/uploads",
    ]

    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "title": "Missing HSTS Header",
            "severity": "Medium",
            "description": "HTTP Strict Transport Security (HSTS) header is not set. "
            "This allows downgrade attacks and cookie hijacking.",
            "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' header.",
        },
        "X-Content-Type-Options": {
            "title": "Missing X-Content-Type-Options",
            "severity": "Low",
            "description": "X-Content-Type-Options header is not set. "
            "Browsers may MIME-sniff responses, leading to XSS attacks.",
            "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
        },
        "X-Frame-Options": {
            "title": "Missing X-Frame-Options",
            "severity": "Medium",
            "description": "X-Frame-Options header is not set. "
            "The site may be vulnerable to clickjacking attacks.",
            "recommendation": "Add 'X-Frame-Options: DENY' or "
            "'X-Frame-Options: SAMEORIGIN' header.",
        },
        "Content-Security-Policy": {
            "title": "Missing Content Security Policy",
            "severity": "Medium",
            "description": "Content-Security-Policy header is not set. "
            "This increases the risk of XSS and data injection attacks.",
            "recommendation": "Implement a Content Security Policy header.",
        },
        "X-XSS-Protection": {
            "title": "Missing X-XSS-Protection",
            "severity": "Low",
            "description": "X-XSS-Protection header is not set. "
            "Legacy browsers may not block reflected XSS attacks.",
            "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header.",
        },
        "Referrer-Policy": {
            "title": "Missing Referrer-Policy",
            "severity": "Low",
            "description": "Referrer-Policy header is not set. "
            "Sensitive data may leak via the Referer header.",
            "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
        },
        "Permissions-Policy": {
            "title": "Missing Permissions-Policy",
            "severity": "Low",
            "description": "Permissions-Policy (formerly Feature-Policy) is not set. "
            "Browser features are not restricted.",
            "recommendation": "Add a Permissions-Policy header to restrict browser features.",
        },
    }

    # Technology signatures
    TECH_SIGNATURES = {
        "WordPress": [
            "wp-content", "wp-includes", "wp-json",
            "wordpress", "/xmlrpc.php",
        ],
        "Joomla": [
            "joomla", "/administrator/", "com_content",
        ],
        "Drupal": [
            "drupal", "sites/default/files", "Drupal.settings",
        ],
        "React": [
            "react", "_react", "__NEXT_DATA__", "reactroot",
        ],
        "Angular": [
            "ng-version", "ng-app", "angular",
        ],
        "Vue.js": [
            "vue", "__vue__", "vue-router",
        ],
        "jQuery": [
            "jquery", "jQuery",
        ],
        "Bootstrap": [
            "bootstrap.min.css", "bootstrap.min.js",
        ],
        "Nginx": [
            "nginx",
        ],
        "Apache": [
            "Apache",
        ],
        "PHP": [
            "X-Powered-By: PHP", ".php",
        ],
        "ASP.NET": [
            "ASP.NET", "X-AspNet-Version", "__VIEWSTATE",
        ],
        "Django": [
            "csrfmiddlewaretoken", "django",
        ],
        "Flask": [
            "Werkzeug",
        ],
        "Express": [
            "X-Powered-By: Express",
        ],
        "Laravel": [
            "laravel_session", "XSRF-TOKEN",
        ],
        "Cloudflare": [
            "cloudflare", "cf-ray",
        ],
    }

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "Andy-VulnScanner/1.0",
        on_finding: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the scanner to stop."""
        self._stop_event.set()

    def reset(self) -> None:
        """Reset the stop signal."""
        self._stop_event.clear()

    def _log(self, message: str, tag: str = ""):
        """Log a message via callback."""
        if self.on_log:
            self.on_log(message, tag)

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a scheme."""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        # Remove trailing slash
        return url.rstrip("/")

    def _make_request(
        self, url: str, method: str = "GET"
    ) -> tuple[Optional[object], Optional[str], int]:
        """Make an HTTP request and return (response, body, status_code)."""
        try:
            req = urllib.request.Request(
                url,
                method=method,
                headers={"User-Agent": self.user_agent},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            response = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            body = response.read().decode("utf-8", errors="replace")
            return response, body, response.getcode()
        except urllib.error.HTTPError as e:
            return None, None, e.code
        except (urllib.error.URLError, OSError, ssl.SSLError):
            return None, None, 0

    def scan(self, url: str, check_dirs: bool = True) -> WebScanResult:
        """
        Perform a comprehensive website scan.

        Args:
            url: Target URL to scan.
            check_dirs: Whether to check for common directories.
        """
        self.reset()
        url = self._normalize_url(url)
        result = WebScanResult(url=url)

        total_steps = 5 + (len(self.COMMON_DIRS) if check_dirs else 0)
        current_step = 0

        # Step 1: Resolve IP
        self._log(f"Resolving {url}...", "info")
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        try:
            result.ip_address = socket.gethostbyname(hostname)
            self._log(f"IP: {result.ip_address}", "info")
        except socket.gaierror:
            result.ip_address = "Could not resolve"
            self._log(f"Could not resolve hostname: {hostname}", "error")

        current_step += 1
        if self.on_progress:
            self.on_progress(current_step, total_steps)

        if self._stop_event.is_set():
            return result

        # Step 2: Fetch main page and headers
        self._log("Fetching main page...", "info")
        response, body, status_code = self._make_request(url)
        result.status_code = status_code

        if response:
            result.headers = dict(response.headers)
            result.server = response.headers.get("Server", "Unknown")
            self._log(f"Status: {status_code} | Server: {result.server}", "success")
        elif status_code > 0:
            self._log(f"HTTP {status_code} response (no body)", "warning")
            # Try to get headers from error response
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": self.user_agent}
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            except urllib.error.HTTPError as e:
                result.headers = dict(e.headers)
                result.server = e.headers.get("Server", "Unknown")
            except Exception:
                pass
        else:
            self._log(f"Could not connect to {url}", "error")
            result.findings.append(WebFinding(
                category="info",
                severity="High",
                title="Connection Failed",
                description=f"Could not establish a connection to {url}.",
                recommendation="Verify the URL is correct and the server is running.",
            ))
            return result

        current_step += 1
        if self.on_progress:
            self.on_progress(current_step, total_steps)

        if self._stop_event.is_set():
            return result

        # Step 3: Check security headers
        self._log("\nChecking security headers...", "info")
        self._check_security_headers(result)

        # Check for information disclosure in headers
        self._check_header_disclosure(result)

        current_step += 1
        if self.on_progress:
            self.on_progress(current_step, total_steps)

        if self._stop_event.is_set():
            return result

        # Step 4: SSL/TLS check
        if url.startswith("https://"):
            self._log("\nChecking SSL/TLS...", "info")
            self._check_ssl(result, hostname)
        else:
            self._log("\nNo HTTPS - skipping SSL check", "warning")
            result.findings.append(WebFinding(
                category="ssl",
                severity="High",
                title="No HTTPS",
                description="The site is not using HTTPS. "
                "All traffic is transmitted in plaintext.",
                recommendation="Enable HTTPS with a valid SSL/TLS certificate.",
            ))

        current_step += 1
        if self.on_progress:
            self.on_progress(current_step, total_steps)

        if self._stop_event.is_set():
            return result

        # Step 5: Technology detection
        self._log("\nDetecting technologies...", "info")
        if body:
            self._detect_technologies(result, body)
        if result.technologies:
            self._log(f"Technologies: {', '.join(result.technologies)}", "success")
        else:
            self._log("No specific technologies detected.", "info")

        current_step += 1
        if self.on_progress:
            self.on_progress(current_step, total_steps)

        if self._stop_event.is_set():
            return result

        # Step 6: Directory enumeration
        if check_dirs:
            self._log(f"\nChecking {len(self.COMMON_DIRS)} common directories...", "info")
            for directory in self.COMMON_DIRS:
                if self._stop_event.is_set():
                    break

                dir_url = urljoin(url + "/", directory.lstrip("/"))
                _, _, dir_status = self._make_request(dir_url, method="HEAD")

                if dir_status == 0:
                    # Try GET if HEAD fails
                    _, _, dir_status = self._make_request(dir_url)

                if dir_status in (200, 301, 302, 403):
                    result.directories_found.append(
                        f"{directory} [{dir_status}]"
                    )
                    severity = self._get_dir_severity(directory, dir_status)
                    title = self._get_dir_title(directory)
                    self._log(f"  [{dir_status}] {directory}", "success")

                    finding = WebFinding(
                        category="directory",
                        severity=severity,
                        title=title,
                        description=f"Found: {dir_url} (HTTP {dir_status})",
                        recommendation=self._get_dir_recommendation(directory),
                        detail=f"HTTP Status: {dir_status}",
                    )
                    result.findings.append(finding)
                    if self.on_finding:
                        self.on_finding(finding)

                current_step += 1
                if self.on_progress:
                    self.on_progress(current_step, total_steps)

        return result

    def _check_security_headers(self, result: WebScanResult) -> None:
        """Check for missing or misconfigured security headers."""
        headers_lower = {k.lower(): v for k, v in result.headers.items()}

        for header_name, info in self.SECURITY_HEADERS.items():
            if header_name.lower() not in headers_lower:
                finding = WebFinding(
                    category="header",
                    severity=info["severity"],
                    title=info["title"],
                    description=info["description"],
                    recommendation=info["recommendation"],
                )
                result.findings.append(finding)
                self._log(f"  Missing: {header_name}", "warning")
                if self.on_finding:
                    self.on_finding(finding)
            else:
                self._log(f"  Present: {header_name}", "success")

    def _check_header_disclosure(self, result: WebScanResult) -> None:
        """Check for information disclosure in HTTP headers."""
        headers_lower = {k.lower(): v for k, v in result.headers.items()}

        # Server header with version info
        server = headers_lower.get("server", "")
        if server and re.search(r"[\d.]+", server):
            finding = WebFinding(
                category="header",
                severity="Low",
                title="Server Version Disclosure",
                description=f"Server header reveals version: '{server}'. "
                "This helps attackers identify the server software.",
                recommendation="Configure the server to hide version information.",
                detail=f"Server: {server}",
            )
            result.findings.append(finding)
            if self.on_finding:
                self.on_finding(finding)

        # X-Powered-By header
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            finding = WebFinding(
                category="header",
                severity="Low",
                title="Technology Disclosure (X-Powered-By)",
                description=f"X-Powered-By header reveals: '{powered_by}'. "
                "This helps attackers identify backend technology.",
                recommendation="Remove the X-Powered-By header.",
                detail=f"X-Powered-By: {powered_by}",
            )
            result.findings.append(finding)
            if self.on_finding:
                self.on_finding(finding)

        # Check for cookies without security flags
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                result.findings.append(WebFinding(
                    category="header",
                    severity="Medium",
                    title="Cookie Missing HttpOnly Flag",
                    description="Cookies are set without HttpOnly flag, "
                    "making them accessible via JavaScript (XSS risk).",
                    recommendation="Set HttpOnly flag on all sensitive cookies.",
                ))
            if "secure" not in set_cookie.lower():
                result.findings.append(WebFinding(
                    category="header",
                    severity="Medium",
                    title="Cookie Missing Secure Flag",
                    description="Cookies are set without Secure flag, "
                    "allowing transmission over unencrypted connections.",
                    recommendation="Set Secure flag on all cookies.",
                ))

    def _check_ssl(self, result: WebScanResult, hostname: str) -> None:
        """Check SSL/TLS certificate and configuration."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    result.ssl_info = {
                        "protocol": protocol or "Unknown",
                        "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown",
                        "bits": ssock.cipher()[2] if ssock.cipher() else 0,
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "expires": cert.get("notAfter", "Unknown"),
                        "san": [
                            entry[1]
                            for entry in cert.get("subjectAltName", [])
                        ],
                    }

                    self._log(f"  Protocol: {protocol}", "success")
                    self._log(
                        f"  Cipher: {result.ssl_info['cipher']} "
                        f"({result.ssl_info['bits']} bits)",
                        "success",
                    )
                    self._log(f"  Expires: {cert.get('notAfter', 'N/A')}", "info")

                    # Check for weak protocols
                    if protocol and protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
                        result.findings.append(WebFinding(
                            category="ssl",
                            severity="High",
                            title=f"Weak SSL/TLS Protocol ({protocol})",
                            description=f"Server supports {protocol} which is "
                            "deprecated and has known vulnerabilities.",
                            recommendation="Disable TLSv1 and TLSv1.1. "
                            "Use TLSv1.2 or TLSv1.3 only.",
                        ))

                    # Check certificate expiry
                    expires_str = cert.get("notAfter", "")
                    if expires_str:
                        try:
                            expires = datetime.strptime(
                                expires_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            days_left = (expires - datetime.utcnow()).days
                            if days_left < 0:
                                result.findings.append(WebFinding(
                                    category="ssl",
                                    severity="Critical",
                                    title="SSL Certificate Expired",
                                    description=f"Certificate expired {abs(days_left)} "
                                    "days ago.",
                                    recommendation="Renew the SSL certificate immediately.",
                                ))
                                self._log(
                                    f"  EXPIRED {abs(days_left)} days ago!", "error"
                                )
                            elif days_left < 30:
                                result.findings.append(WebFinding(
                                    category="ssl",
                                    severity="Medium",
                                    title="SSL Certificate Expiring Soon",
                                    description=f"Certificate expires in {days_left} days.",
                                    recommendation="Renew the SSL certificate soon.",
                                ))
                                self._log(
                                    f"  Expires in {days_left} days!", "warning"
                                )
                            else:
                                self._log(
                                    f"  Valid for {days_left} more days", "success"
                                )
                        except ValueError:
                            pass

        except ssl.SSLCertVerificationError as e:
            error_msg = str(e)
            result.ssl_info = {"error": error_msg}
            self._log(f"  SSL verification failed: {error_msg}", "error")

            if "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
                result.findings.append(WebFinding(
                    category="ssl",
                    severity="High",
                    title="Self-Signed SSL Certificate",
                    description="The server uses a self-signed certificate "
                    "which is not trusted by browsers.",
                    recommendation="Use a certificate from a trusted CA "
                    "(e.g., Let's Encrypt).",
                ))
            else:
                result.findings.append(WebFinding(
                    category="ssl",
                    severity="High",
                    title="SSL Certificate Verification Failed",
                    description=f"SSL certificate issue: {error_msg}",
                    recommendation="Fix the SSL certificate configuration.",
                ))

        except (OSError, ssl.SSLError) as e:
            result.ssl_info = {"error": str(e)}
            self._log(f"  SSL check failed: {e}", "error")

    def _detect_technologies(
        self, result: WebScanResult, body: str
    ) -> None:
        """Detect web technologies from response body and headers."""
        combined = body.lower()
        headers_str = str(result.headers).lower()

        for tech, signatures in self.TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined or sig.lower() in headers_str:
                    if tech not in result.technologies:
                        result.technologies.append(tech)
                    break

        # Detect from server header
        server = result.server.lower()
        if "nginx" in server and "Nginx" not in result.technologies:
            result.technologies.append("Nginx")
        if "apache" in server and "Apache" not in result.technologies:
            result.technologies.append("Apache")
        if "iis" in server.lower() and "IIS" not in result.technologies:
            result.technologies.append("IIS")

        # Check for outdated jQuery
        jquery_match = re.search(r'jquery[/\-](\d+\.\d+\.\d+)', combined)
        if jquery_match:
            version = jquery_match.group(1)
            major = int(version.split(".")[0])
            if major < 3:
                result.findings.append(WebFinding(
                    category="technology",
                    severity="Medium",
                    title=f"Outdated jQuery ({version})",
                    description=f"jQuery version {version} is outdated and may "
                    "contain known vulnerabilities.",
                    recommendation="Update jQuery to the latest version (3.x).",
                ))

        # Check for WordPress-specific issues
        if "WordPress" in result.technologies:
            wp_version = re.search(
                r'<meta name="generator" content="WordPress (\d+\.\d+[\.\d]*)"',
                body,
            )
            if wp_version:
                result.findings.append(WebFinding(
                    category="technology",
                    severity="Low",
                    title=f"WordPress Version Exposed ({wp_version.group(1)})",
                    description="WordPress version is exposed in the page source.",
                    recommendation="Remove the WordPress version meta tag.",
                ))

    def _get_dir_severity(self, directory: str, status: int) -> str:
        """Get severity level for a discovered directory."""
        sensitive = [
            "/.env", "/.git/config", "/.htaccess",
            "/backup", "/config", "/debug",
            "/phpmyadmin", "/server-status", "/server-info",
            "/console", "/xmlrpc.php",
        ]
        admin_paths = [
            "/admin", "/administrator", "/wp-admin",
            "/cpanel", "/wp-login.php", "/login",
        ]

        if directory in sensitive and status == 200:
            return "Critical"
        if directory in sensitive and status == 403:
            return "Medium"
        if directory in admin_paths and status in (200, 301, 302):
            return "Medium"
        if status == 200:
            return "Low"
        return "Info"

    def _get_dir_title(self, directory: str) -> str:
        """Get a descriptive title for a discovered directory."""
        titles = {
            "/.env": "Environment File Exposed",
            "/.git/config": "Git Configuration Exposed",
            "/.htaccess": "Apache .htaccess Exposed",
            "/admin": "Admin Panel Found",
            "/administrator": "Admin Panel Found",
            "/wp-admin": "WordPress Admin Found",
            "/wp-login.php": "WordPress Login Found",
            "/phpmyadmin": "phpMyAdmin Found",
            "/cpanel": "cPanel Found",
            "/robots.txt": "Robots.txt Found",
            "/sitemap.xml": "Sitemap Found",
            "/backup": "Backup Directory Found",
            "/config": "Config Directory Found",
            "/debug": "Debug Endpoint Found",
            "/console": "Console Endpoint Found",
            "/server-status": "Apache Server Status Exposed",
            "/server-info": "Apache Server Info Exposed",
            "/xmlrpc.php": "XML-RPC Endpoint Found",
            "/swagger": "Swagger API Docs Found",
            "/docs": "API Documentation Found",
            "/api": "API Endpoint Found",
            "/security.txt": "Security.txt Found",
            "/.well-known/security.txt": "Security.txt Found",
        }
        return titles.get(directory, f"Directory Found: {directory}")

    def _get_dir_recommendation(self, directory: str) -> str:
        """Get a recommendation for a discovered directory."""
        recs = {
            "/.env": "Remove .env file from web root immediately! "
            "It may contain secrets and credentials.",
            "/.git/config": "Block access to .git directory. "
            "Source code may be exposed.",
            "/.htaccess": "Ensure .htaccess is not publicly readable.",
            "/admin": "Restrict admin panel access by IP or VPN.",
            "/phpmyadmin": "Remove or restrict phpMyAdmin access. "
            "Use SSH tunneling instead.",
            "/backup": "Remove backup files from web root.",
            "/debug": "Disable debug endpoints in production.",
            "/console": "Disable debug console in production.",
            "/server-status": "Restrict Apache server-status to localhost.",
            "/server-info": "Restrict Apache server-info to localhost.",
            "/xmlrpc.php": "Disable XML-RPC if not needed "
            "(common brute force target).",
            "/robots.txt": "Review robots.txt for sensitive path disclosure.",
            "/swagger": "Restrict API documentation access in production.",
        }
        return recs.get(
            directory,
            "Review if this path should be publicly accessible.",
        )
