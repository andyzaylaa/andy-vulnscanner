"""Brute Force Login scanner for Andy VulnScanner.

Tests login pages with username/password combinations
for HTTP form-based, SSH, and FTP authentication.
"""

import ftplib
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class BruteFinding:
    """Represents a brute force finding."""

    scanner: str  # "http_brute", "ssh_brute", "ftp_brute"
    severity: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class BruteResult:
    """Result of a brute force scan."""

    target: str
    findings: list[BruteFinding] = field(default_factory=list)
    credentials_found: int = 0
    attempts: int = 0
    scan_time: float = 0.0


class BruteForceScanner:
    """Test login interfaces with common credentials."""

    # Common usernames to test
    USERNAMES = [
        "admin", "administrator", "root", "user", "test",
        "guest", "operator", "manager", "webmaster",
        "info", "support", "demo", "ftp", "www",
    ]

    # Common passwords to test
    PASSWORDS = [
        "admin", "password", "123456", "12345678", "root",
        "toor", "pass", "test", "guest", "master",
        "changeme", "letmein", "welcome", "monkey", "dragon",
        "login", "abc123", "qwerty", "password1", "admin123",
        "1234", "default", "P@ssw0rd", "admin1",
    ]

    # Common login form paths
    LOGIN_PATHS = [
        "/login", "/admin/login", "/admin", "/wp-login.php",
        "/user/login", "/signin", "/auth/login", "/account/login",
        "/panel/login", "/administrator", "/manager/html",
    ]

    # Common form field names for username
    USERNAME_FIELDS = [
        "username", "user", "login", "email", "name",
        "user_login", "log", "usr", "userid",
    ]

    # Common form field names for password
    PASSWORD_FIELDS = [
        "password", "pass", "passwd", "pwd", "user_pass",
        "login_password", "passwort",
    ]

    def __init__(
        self,
        timeout: float = 5.0,
        threads: int = 5,
        on_finding: Optional[Callable[[BruteFinding], None]] = None,
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
        self._stop_event.set()

    def reset(self):
        self._stop_event.clear()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    def _report(self, finding: BruteFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helper ──────────────────────────────────────────────────

    def _make_request(
        self, url: str, data: Optional[bytes] = None,
        method: str = "GET", headers: Optional[dict] = None,
        timeout: Optional[float] = None,
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
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
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
        http_brute: bool = True,
        ftp_brute: bool = True,
        ssh_brute: bool = True,
    ) -> BruteResult:
        """Run brute force tests against the target."""
        self.reset()
        result = BruteResult(target=target)
        start_time = time.time()

        total = sum([http_brute, ftp_brute, ssh_brute])
        current = 0

        if http_brute and not self._stopped():
            self._log("Starting HTTP Login Brute Force...", "header")
            self._brute_http(target, result)
            current += 1
            self._progress(current, total)

        if ftp_brute and not self._stopped():
            self._log("\nStarting FTP Brute Force...", "header")
            self._brute_ftp(target, result)
            current += 1
            self._progress(current, total)

        if ssh_brute and not self._stopped():
            self._log("\nStarting SSH Brute Force Check...", "header")
            self._brute_ssh(target, result)
            current += 1
            self._progress(current, total)

        result.scan_time = time.time() - start_time
        return result

    # ── HTTP Login Brute Force ───────────────────────────────────────

    def _brute_http(self, target: str, result: BruteResult):
        """Brute force HTTP login forms."""
        base_url = self._normalize_url(target)

        # Find login pages
        self._log("  Searching for login pages...", "info")
        login_url = None
        login_page_body = ""

        for path in self.LOGIN_PATHS:
            if self._stopped():
                return
            url = f"{base_url}{path}"
            status, _, body = self._make_request(url)
            if status == 200 and self._has_login_form(body):
                login_url = url
                login_page_body = body
                self._log(f"  Found login page: {path}", "success")
                break

        if not login_url:
            self._log("  No login pages found.", "info")
            finding = BruteFinding(
                scanner="http_brute",
                severity="Info",
                title="No HTTP Login Pages Found",
                description=(
                    "No login forms were detected at common paths. "
                    "The application may use a non-standard login URL."
                ),
                recommendation="Manually verify login page locations.",
            )
            result.findings.append(finding)
            self._report(finding)
            return

        # Detect form fields
        user_field = self._detect_field(login_page_body, self.USERNAME_FIELDS)
        pass_field = self._detect_field(login_page_body, self.PASSWORD_FIELDS)

        if not user_field or not pass_field:
            self._log(
                "  Could not detect login form fields.", "warning",
            )
            return

        self._log(
            f"  Form fields: username={user_field}, password={pass_field}",
            "info",
        )

        # Test credentials
        attempts = 0
        found_creds = []
        total_combos = len(self.USERNAMES) * len(self.PASSWORDS)
        self._log(
            f"  Testing {total_combos} credential combinations...", "info",
        )

        for username in self.USERNAMES:
            if self._stopped():
                break
            for password in self.PASSWORDS:
                if self._stopped():
                    break
                attempts += 1
                result.attempts += 1

                if attempts % 50 == 0:
                    self._log(
                        f"  Progress: {attempts}/{total_combos} attempts...",
                        "info",
                    )

                success = self._try_http_login(
                    login_url, user_field, pass_field,
                    username, password,
                )
                if success:
                    found_creds.append((username, password))
                    self._log(
                        f"  VALID: {username}:{password}", "error",
                    )
                    result.credentials_found += 1

                    finding = BruteFinding(
                        scanner="http_brute",
                        severity="Critical",
                        title=f"HTTP Login Credentials Found: {username}",
                        description=(
                            f"Valid credentials discovered at {login_url}. "
                            f"Username '{username}' with a weak/default password."
                        ),
                        evidence=f"URL: {login_url}\nUsername: {username}\nPassword: {password}",
                        recommendation=(
                            "Immediately change this password. Implement "
                            "account lockout policies, rate limiting, and "
                            "require strong passwords. Consider 2FA."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)

                # Small delay to avoid overwhelming the server
                time.sleep(0.1)

        if not found_creds:
            finding = BruteFinding(
                scanner="http_brute",
                severity="Info",
                title="No Weak HTTP Credentials Found",
                description=(
                    f"Tested {attempts} credential combinations against "
                    f"{login_url}. No weak/default credentials detected."
                ),
                evidence=f"Login URL: {login_url}\nAttempts: {attempts}",
                recommendation=(
                    "Continue to enforce strong password policies. "
                    "Ensure rate limiting and account lockout are in place."
                ),
            )
            result.findings.append(finding)
            self._report(finding)

        # Check for rate limiting
        if attempts > 10:
            self._check_rate_limiting(login_url, user_field, pass_field, result)

        self._log(
            f"  HTTP brute force complete. {attempts} attempts, "
            f"{len(found_creds)} credentials found.", "info",
        )

    def _has_login_form(self, body: str) -> bool:
        """Check if page contains a login form."""
        lower = body.lower()
        has_form = "<form" in lower
        has_password = 'type="password"' in lower or "type='password'" in lower
        return has_form and has_password

    def _detect_field(self, body: str, field_names: list[str]) -> str:
        """Detect form field name from HTML."""
        lower = body.lower()
        for name in field_names:
            pattern = rf'name\s*=\s*["\']({re.escape(name)})["\']'
            match = re.search(pattern, lower)
            if match:
                return match.group(1)
        return ""

    def _try_http_login(
        self, url: str, user_field: str, pass_field: str,
        username: str, password: str,
    ) -> bool:
        """Attempt HTTP form login and check if successful."""
        post_data = urllib.parse.urlencode({
            user_field: username,
            pass_field: password,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        status, resp_headers, body = self._make_request(
            url, data=post_data, method="POST", headers=headers,
        )

        if status == 0:
            return False

        # Heuristic: check for login failure indicators
        lower_body = body.lower()
        failure_indicators = [
            "invalid", "incorrect", "wrong", "failed",
            "error", "denied", "try again", "not found",
            "bad credentials", "authentication failed",
            "login failed", "invalid username",
        ]
        success_indicators = [
            "dashboard", "welcome", "logout", "sign out",
            "my account", "profile", "settings",
        ]

        has_failure = any(ind in lower_body for ind in failure_indicators)
        has_success = any(ind in lower_body for ind in success_indicators)

        # Redirect to dashboard is also a success indicator
        if status in (301, 302, 303):
            location = resp_headers.get("Location", "").lower()
            if any(
                kw in location for kw in
                ["dashboard", "admin", "panel", "home", "index"]
            ):
                return True

        return has_success and not has_failure

    def _check_rate_limiting(
        self, url: str, user_field: str, pass_field: str,
        result: BruteResult,
    ):
        """Check if login has rate limiting."""
        self._log("  Checking for rate limiting...", "info")
        blocked = False

        for i in range(10):
            if self._stopped():
                return
            post_data = urllib.parse.urlencode({
                user_field: f"ratetest{i}",
                pass_field: "ratetest",
            }).encode("utf-8")
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            status, _, body = self._make_request(
                url, data=post_data, method="POST", headers=headers,
            )
            lower = body.lower()
            if status == 429 or "rate limit" in lower or "too many" in lower:
                blocked = True
                break
            if status == 403 and ("blocked" in lower or "banned" in lower):
                blocked = True
                break

        if not blocked:
            finding = BruteFinding(
                scanner="http_brute",
                severity="Medium",
                title="No Rate Limiting on Login Page",
                description=(
                    "The login page does not appear to implement rate "
                    "limiting. This makes it vulnerable to brute force "
                    "attacks."
                ),
                evidence=f"URL: {url}\n10 rapid login attempts were not blocked.",
                recommendation=(
                    "Implement rate limiting (e.g., max 5 attempts per "
                    "minute). Add CAPTCHA after failed attempts. Consider "
                    "account lockout after multiple failures."
                ),
            )
            result.findings.append(finding)
            self._report(finding)
        else:
            self._log("  Rate limiting detected (good).", "success")

    # ── FTP Brute Force ──────────────────────────────────────────────

    def _brute_ftp(self, target: str, result: BruteResult):
        """Brute force FTP login."""
        # Extract hostname
        host = target
        if "://" in host:
            host = urllib.parse.urlparse(target).netloc
        if ":" in host:
            host = host.split(":")[0]

        # Check if FTP port is open
        self._log(f"  Checking FTP service on {host}:21...", "info")
        try:
            sock = socket.create_connection((host, 21), timeout=self.timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()
            self._log(f"  FTP banner: {banner.strip()}", "success")
        except Exception:
            self._log("  FTP port 21 is not open or reachable.", "info")
            return

        # Check anonymous login first
        self._log("  Testing anonymous FTP login...", "info")
        if self._try_ftp_login(host, "anonymous", "anonymous@test.com"):
            finding = BruteFinding(
                scanner="ftp_brute",
                severity="High",
                title="Anonymous FTP Login Allowed",
                description=(
                    f"FTP server on {host} allows anonymous login. "
                    "This may expose sensitive files."
                ),
                evidence=f"Host: {host}\nUsername: anonymous",
                recommendation=(
                    "Disable anonymous FTP access unless explicitly "
                    "required. Review files accessible via anonymous login."
                ),
            )
            result.findings.append(finding)
            self._report(finding)
            result.credentials_found += 1

        # Test common credentials
        ftp_users = ["admin", "root", "ftp", "user", "test", "www"]
        ftp_passwords = [
            "admin", "password", "123456", "root", "ftp",
            "test", "guest", "changeme", "pass",
        ]

        attempts = 0
        total = len(ftp_users) * len(ftp_passwords)
        self._log(f"  Testing {total} FTP credential combinations...", "info")

        for username in ftp_users:
            if self._stopped():
                break
            for password in ftp_passwords:
                if self._stopped():
                    break
                attempts += 1
                result.attempts += 1

                if self._try_ftp_login(host, username, password):
                    self._log(
                        f"  VALID FTP: {username}:{password}", "error",
                    )
                    result.credentials_found += 1

                    finding = BruteFinding(
                        scanner="ftp_brute",
                        severity="Critical",
                        title=f"FTP Credentials Found: {username}",
                        description=(
                            f"Valid FTP credentials on {host}. "
                            f"Username '{username}' with weak password."
                        ),
                        evidence=f"Host: {host}:21\nUsername: {username}\nPassword: {password}",
                        recommendation=(
                            "Change password immediately. Consider using "
                            "SFTP instead of FTP. Implement fail2ban."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)

                time.sleep(0.2)

        self._log(
            f"  FTP brute force complete. {attempts} attempts.", "info",
        )

    def _try_ftp_login(self, host: str, username: str, password: str) -> bool:
        """Attempt FTP login."""
        try:
            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(host, 21)
            ftp.login(username, password)
            ftp.quit()
            return True
        except Exception:
            return False

    # ── SSH Brute Force Check ────────────────────────────────────────

    def _brute_ssh(self, target: str, result: BruteResult):
        """Check SSH for weak configurations (no actual brute force).

        Note: Actual SSH brute force requires paramiko which may not
        be available. Instead, we check SSH configuration and report
        findings.
        """
        host = target
        if "://" in host:
            host = urllib.parse.urlparse(target).netloc
        if ":" in host:
            host = host.split(":")[0]

        # Check if SSH port is open
        self._log(f"  Checking SSH service on {host}:22...", "info")
        try:
            sock = socket.create_connection((host, 22), timeout=self.timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            self._log(f"  SSH banner: {banner}", "success")
        except Exception:
            self._log("  SSH port 22 is not open or reachable.", "info")
            return

        # Analyze SSH banner for version info
        if banner:
            finding = BruteFinding(
                scanner="ssh_brute",
                severity="Info",
                title=f"SSH Service Detected on {host}",
                description=f"SSH service is running with banner: {banner}",
                evidence=f"Host: {host}:22\nBanner: {banner}",
                recommendation="Ensure SSH is properly configured with key-based auth.",
            )
            result.findings.append(finding)
            self._report(finding)

            # Check for old SSH versions
            banner_lower = banner.lower()
            if "openssh" in banner_lower:
                version_match = re.search(r"openssh[_\s]*([\d.]+)", banner_lower)
                if version_match:
                    version = version_match.group(1)
                    try:
                        major, minor = version.split(".")[:2]
                        if int(major) < 7 or (int(major) == 7 and int(minor) < 4):
                            finding = BruteFinding(
                                scanner="ssh_brute",
                                severity="High",
                                title=f"Outdated SSH Version: OpenSSH {version}",
                                description=(
                                    f"The SSH server is running OpenSSH {version}. "
                                    "Older versions may have known vulnerabilities."
                                ),
                                evidence=f"Banner: {banner}",
                                recommendation=(
                                    "Update OpenSSH to the latest stable version. "
                                    "Run: sudo apt update && sudo apt upgrade openssh-server"
                                ),
                            )
                            result.findings.append(finding)
                            self._report(finding)
                    except (ValueError, IndexError):
                        pass

            # Check for password authentication hint
            if "dropbear" in banner_lower:
                finding = BruteFinding(
                    scanner="ssh_brute",
                    severity="Low",
                    title="Dropbear SSH Server Detected",
                    description=(
                        "The server uses Dropbear SSH instead of OpenSSH. "
                        "Dropbear is common on embedded devices and may "
                        "have limited security features."
                    ),
                    evidence=f"Banner: {banner}",
                    recommendation=(
                        "Consider using OpenSSH for better security features. "
                        "Ensure Dropbear is up to date."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)

        # General SSH security recommendations
        finding = BruteFinding(
            scanner="ssh_brute",
            severity="Low",
            title="SSH Security Recommendations",
            description=(
                "SSH is accessible. Verify the following security settings."
            ),
            evidence=f"Host: {host}:22",
            recommendation=(
                "1. Disable password authentication (use key-based only)\n"
                "2. Disable root login (PermitRootLogin no)\n"
                "3. Use fail2ban to prevent brute force\n"
                "4. Change default SSH port if possible\n"
                "5. Limit SSH access with AllowUsers/AllowGroups"
            ),
        )
        result.findings.append(finding)
        self._report(finding)

        self._log("  SSH check complete.", "info")
