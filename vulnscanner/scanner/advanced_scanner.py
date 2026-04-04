"""Advanced vulnerability scanning module for Andy VulnScanner.

Includes SQL Injection, XSS, CSRF, Open Redirect, CORS misconfiguration,
and Cookie Security scanners.
"""

import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class AdvFinding:
    """Represents a single advanced scanning finding."""

    scanner: str  # "sqli", "xss", "csrf", "redirect", "cors", "cookie"
    severity: str  # "Critical", "High", "Medium", "Low", "Info"
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    payload: str = ""
    parameter: str = ""


@dataclass
class AdvScanResult:
    """Result of an advanced vulnerability scan."""

    url: str
    findings: list[AdvFinding] = field(default_factory=list)
    forms_found: int = 0
    parameters_tested: int = 0
    scan_time: float = 0.0


class AdvancedScanner:
    """Perform advanced web vulnerability scanning."""

    # ── SQL Injection ─────────────────────────────────────────────────

    # Error patterns that indicate SQL injection
    SQL_ERRORS = {
        "MySQL": [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
        ],
        "PostgreSQL": [
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
        ],
        "MSSQL": [
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"OLE DB.*? SQL Server",
            r"(\bSQL Server\b.*?\bDriver\b|\bODBC\b.*?\bSQL Server\b)",
            r"SQLServer JDBC Driver",
            r"SqlClient\.",
            r"macabordar SQL Server",
            r"Unclosed quotation mark after the character string",
        ],
        "Oracle": [
            r"\bORA-\d{5}",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_",
            r"quoted string not properly terminated",
        ],
        "SQLite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?sqlite_",
            r"Warning.*?SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLITE_CONSTRAINT",
        ],
        "Generic": [
            r"SQL syntax",
            r"sql error",
            r"syntax error",
            r"unterminated quoted string",
            r"unexpected end of SQL command",
            r"unrecognized token",
        ],
    }

    # SQL injection test payloads
    SQLI_PAYLOADS = [
        ("'", "Single quote"),
        ("\"", "Double quote"),
        ("' OR '1'='1", "Boolean-based OR (single quote)"),
        ("\" OR \"1\"=\"1", "Boolean-based OR (double quote)"),
        ("' OR '1'='1' --", "Boolean-based with comment"),
        ("1' ORDER BY 1--", "ORDER BY enumeration"),
        ("1 UNION SELECT NULL--", "UNION-based (single NULL)"),
        ("'; WAITFOR DELAY '0:0:5'--", "Time-based (MSSQL)"),
        ("1; SELECT SLEEP(5)--", "Time-based (MySQL)"),
        ("' AND 1=1--", "AND-based true condition"),
        ("' AND 1=2--", "AND-based false condition"),
        ("1' OR '1'='1' /*", "Boolean OR with block comment"),
        ("-1 OR 1=1", "Numeric OR injection"),
        ("admin'--", "Auth bypass attempt"),
    ]

    # ── XSS ───────────────────────────────────────────────────────────

    XSS_PAYLOADS = [
        ("<script>alert('XSS')</script>", "Basic script tag"),
        ("<img src=x onerror=alert('XSS')>", "Image error handler"),
        ("<svg onload=alert('XSS')>", "SVG onload"),
        ("javascript:alert('XSS')", "JavaScript URI"),
        ("'\"><script>alert('XSS')</script>", "Breaking out of attribute"),
        ("<body onload=alert('XSS')>", "Body onload"),
        ("<input onfocus=alert('XSS') autofocus>", "Input autofocus"),
        ("<marquee onstart=alert('XSS')>", "Marquee onstart"),
        ("'-alert('XSS')-'", "Template literal injection"),
        ("<details open ontoggle=alert('XSS')>", "Details ontoggle"),
        ("\"><img src=x onerror=alert('XSS')>", "Attribute breakout img"),
        ("<iframe src=\"javascript:alert('XSS')\">", "Iframe javascript src"),
    ]

    # ── Open Redirect ─────────────────────────────────────────────────

    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnTo", "next", "goto", "target", "dest",
        "destination", "rurl", "out", "continue", "link", "forward",
    ]

    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%00",
        "//evil.com/%2f..",
    ]

    # ── Common Directories for Form Discovery ────────────────────────

    FORM_PAGES = [
        "/", "/login", "/register", "/signup", "/contact",
        "/search", "/admin", "/forgot-password", "/reset-password",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        on_finding: Optional[Callable[[AdvFinding], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
    ):
        self.timeout = timeout
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

    def _report(self, finding: AdvFinding):
        if self.on_finding:
            self.on_finding(finding)

    def _progress(self, current: int, total: int):
        if self.on_progress:
            self.on_progress(current, total)

    # ── HTTP helpers ──────────────────────────────────────────────────

    def _make_request(
        self, url: str, method: str = "GET", data: Optional[bytes] = None,
        headers: Optional[dict] = None, timeout: Optional[float] = None,
    ) -> tuple[int, dict, str]:
        """Make an HTTP request and return (status, headers, body).

        Headers are returned as a dict. Use ``_make_request_raw`` if you
        need access to duplicate header values (e.g. multiple Set-Cookie).
        """
        status, raw_headers, body = self._make_request_raw(
            url, method=method, data=data, headers=headers, timeout=timeout,
        )
        return status, dict(raw_headers) if raw_headers else {}, body

    def _make_request_raw(
        self, url: str, method: str = "GET", data: Optional[bytes] = None,
        headers: Optional[dict] = None, timeout: Optional[float] = None,
    ) -> tuple[int, object, str]:
        """Make an HTTP request, preserving the raw HTTPMessage headers."""
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

        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        tout = timeout or self.timeout

        try:
            with urllib.request.urlopen(req, timeout=tout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, resp.headers, body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, e.headers, body
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
        url: str,
        sqli: bool = True,
        xss: bool = True,
        csrf: bool = True,
        open_redirect: bool = True,
        cors: bool = True,
        cookies: bool = True,
    ) -> AdvScanResult:
        """Run all selected advanced scans against the target URL."""
        self.reset()
        url = self._normalize_url(url)
        result = AdvScanResult(url=url)

        # Count total steps for progress
        total = 0
        if sqli:
            total += 1
        if xss:
            total += 1
        if csrf:
            total += 1
        if open_redirect:
            total += 1
        if cors:
            total += 1
        if cookies:
            total += 1
        current = 0

        # 1. SQL Injection
        if sqli and not self._stopped():
            self._log("Starting SQL Injection scan...", "header")
            self._scan_sqli(url, result)
            current += 1
            self._progress(current, total)

        # 2. XSS
        if xss and not self._stopped():
            self._log("\nStarting XSS scan...", "header")
            self._scan_xss(url, result)
            current += 1
            self._progress(current, total)

        # 3. CSRF
        if csrf and not self._stopped():
            self._log("\nStarting CSRF scan...", "header")
            self._scan_csrf(url, result)
            current += 1
            self._progress(current, total)

        # 4. Open Redirect
        if open_redirect and not self._stopped():
            self._log("\nStarting Open Redirect scan...", "header")
            self._scan_open_redirect(url, result)
            current += 1
            self._progress(current, total)

        # 5. CORS
        if cors and not self._stopped():
            self._log("\nStarting CORS misconfiguration scan...", "header")
            self._scan_cors(url, result)
            current += 1
            self._progress(current, total)

        # 6. Cookie Security
        if cookies and not self._stopped():
            self._log("\nStarting Cookie Security scan...", "header")
            self._scan_cookies(url, result)
            current += 1
            self._progress(current, total)

        return result

    # ── SQL Injection Scanner ─────────────────────────────────────────

    def _scan_sqli(self, url: str, result: AdvScanResult):
        """Test URL parameters for SQL injection vulnerabilities."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try to discover parameters from forms
            self._log("  No URL parameters found, checking page for forms...", "info")
            params = self._discover_params(url)
            if not params:
                self._log("  No injectable parameters found.", "info")
                # Still test the base URL with common param names
                params = {"id": ["1"], "page": ["1"], "q": ["test"]}
                self._log(
                    f"  Testing {len(params)} common parameter names...", "info",
                )

        tested = 0
        for param_name in params:
            if self._stopped():
                break

            self._log(f"  Testing parameter: {param_name}", "info")

            for payload, desc in self.SQLI_PAYLOADS:
                if self._stopped():
                    break

                # Build test URL
                test_params = dict(params)
                test_params[param_name] = [payload]
                query = urllib.parse.urlencode(
                    {k: v[0] for k, v in test_params.items()},
                )
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment,
                ))

                status, _, body = self._make_request(test_url, timeout=8)
                tested += 1

                if status == 0:
                    continue

                # Check for SQL error messages
                for db_type, patterns in self.SQL_ERRORS.items():
                    for pattern in patterns:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            finding = AdvFinding(
                                scanner="sqli",
                                severity="Critical",
                                title=f"SQL Injection ({db_type})",
                                description=(
                                    f"SQL injection vulnerability detected in "
                                    f"parameter '{param_name}'. The server "
                                    f"returned a {db_type} database error."
                                ),
                                evidence=match.group(0)[:200],
                                payload=payload,
                                parameter=param_name,
                                recommendation=(
                                    "Use parameterized queries or prepared "
                                    "statements. Never concatenate user input "
                                    "into SQL queries directly."
                                ),
                            )
                            result.findings.append(finding)
                            self._report(finding)
                            self._log(
                                f"  FOUND: {db_type} SQL error with "
                                f"payload: {desc}", "error",
                            )
                            break
                    else:
                        continue
                    break

                # Check for boolean-based blind SQLi (compare responses)
                if "AND 1=1" in payload or "OR '1'='1" in payload:
                    # Get baseline response
                    baseline_params = dict(params)
                    baseline_query = urllib.parse.urlencode(
                        {k: v[0] for k, v in baseline_params.items()},
                    )
                    baseline_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, baseline_query, parsed.fragment,
                    ))
                    _, _, baseline_body = self._make_request(baseline_url)

                    if (
                        baseline_body
                        and body
                        and len(body) != len(baseline_body)
                        and abs(len(body) - len(baseline_body)) > 50
                    ):
                        finding = AdvFinding(
                            scanner="sqli",
                            severity="High",
                            title="Possible Blind SQL Injection",
                            description=(
                                f"Possible blind SQL injection in parameter "
                                f"'{param_name}'. Response length differs "
                                f"significantly with boolean payload "
                                f"({len(baseline_body)} vs {len(body)} bytes)."
                            ),
                            payload=payload,
                            parameter=param_name,
                            recommendation=(
                                "Use parameterized queries. Investigate "
                                "the parameter for SQL injection manually."
                            ),
                        )
                        result.findings.append(finding)
                        self._report(finding)
                        self._log(
                            f"  POSSIBLE: Blind SQLi in '{param_name}' "
                            f"(response diff: "
                            f"{abs(len(body) - len(baseline_body))} bytes)",
                            "warning",
                        )

        result.parameters_tested += tested
        self._log(f"  SQL Injection scan complete. Tested {tested} payloads.", "info")

    def _discover_params(self, url: str) -> dict:
        """Discover parameters from HTML forms on the page."""
        _, _, body = self._make_request(url)
        if not body:
            return {}

        params = {}
        # Find input fields
        inputs = re.findall(
            r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE,
        )
        for name in inputs:
            if name.lower() not in ("csrf", "token", "_token", "csrf_token"):
                params[name] = ["test"]

        return params

    # ── XSS Scanner ───────────────────────────────────────────────────

    def _scan_xss(self, url: str, result: AdvScanResult):
        """Test for reflected XSS vulnerabilities."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            # Try common parameter names
            params = {"q": ["test"], "search": ["test"], "query": ["test"]}
            self._log(
                f"  No URL parameters, testing {len(params)} common names...",
                "info",
            )

        tested = 0
        for param_name in params:
            if self._stopped():
                break

            self._log(f"  Testing parameter: {param_name}", "info")

            for payload, desc in self.XSS_PAYLOADS:
                if self._stopped():
                    break

                # Build test URL
                test_params = dict(params)
                test_params[param_name] = [payload]
                query = urllib.parse.urlencode(
                    {k: v[0] for k, v in test_params.items()},
                )
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment,
                ))

                status, _, body = self._make_request(test_url)
                tested += 1

                if status == 0 or not body:
                    continue

                # Check if payload is reflected in the response
                if payload in body:
                    finding = AdvFinding(
                        scanner="xss",
                        severity="High",
                        title="Reflected XSS Vulnerability",
                        description=(
                            f"Reflected Cross-Site Scripting (XSS) detected "
                            f"in parameter '{param_name}'. The payload is "
                            f"reflected without sanitization."
                        ),
                        evidence=f"Payload reflected: {payload[:80]}",
                        payload=payload,
                        parameter=param_name,
                        recommendation=(
                            "Sanitize and encode all user input before "
                            "reflecting it in HTML output. Use Content-"
                            "Security-Policy headers to mitigate XSS."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    self._log(
                        f"  FOUND: Reflected XSS with: {desc}", "error",
                    )
                    break  # One finding per parameter is enough

                # Check for partial reflection (without full payload)
                # This could indicate filtered but bypassable XSS
                stripped = re.sub(r'<[^>]*>', '', payload)
                if stripped and stripped in body and len(stripped) > 5:
                    finding = AdvFinding(
                        scanner="xss",
                        severity="Medium",
                        title="Possible XSS (Partial Reflection)",
                        description=(
                            f"Input in parameter '{param_name}' is partially "
                            f"reflected in the response. HTML tags may be "
                            f"stripped but the payload content appears."
                        ),
                        evidence=f"Partial reflection of: {payload[:80]}",
                        payload=payload,
                        parameter=param_name,
                        recommendation=(
                            "Review input sanitization. Ensure all special "
                            "characters are properly encoded."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    self._log(
                        f"  POSSIBLE: Partial reflection with: {desc}",
                        "warning",
                    )
                    break

        result.parameters_tested += tested
        self._log(f"  XSS scan complete. Tested {tested} payloads.", "info")

    # ── CSRF Scanner ──────────────────────────────────────────────────

    def _scan_csrf(self, url: str, result: AdvScanResult):
        """Check for missing CSRF protection on forms."""
        pages_to_check = [url]
        parsed = urllib.parse.urlparse(url)

        # Also check common form pages
        for page in self.FORM_PAGES:
            full_url = f"{parsed.scheme}://{parsed.netloc}{page}"
            if full_url != url:
                pages_to_check.append(full_url)

        forms_found = 0
        forms_without_csrf = 0

        for page_url in pages_to_check:
            if self._stopped():
                break

            status, _, body = self._make_request(page_url)
            if status == 0 or not body:
                continue

            # Find all forms (capture the tag and content separately)
            forms = re.findall(
                r'(<form[^>]*>)(.*?)</form>', body,
                re.IGNORECASE | re.DOTALL,
            )

            for form_tag_str, form_html in forms:
                forms_found += 1

                # Check if this specific form has POST method
                is_post = re.search(
                    r'method=["\']?post["\']?',
                    form_tag_str, re.IGNORECASE,
                )
                if not is_post:
                    continue

                # Check for CSRF token
                csrf_patterns = [
                    r'name=["\']csrf',
                    r'name=["\']_token',
                    r'name=["\']token',
                    r'name=["\']csrfmiddlewaretoken',
                    r'name=["\']__RequestVerificationToken',
                    r'name=["\']authenticity_token',
                    r'name=["\']_csrf',
                    r'name=["\']nonce',
                    r'x-csrf-token',
                ]

                has_csrf = False
                for pattern in csrf_patterns:
                    if re.search(pattern, form_html, re.IGNORECASE):
                        has_csrf = True
                        break

                if not has_csrf:
                    forms_without_csrf += 1
                    finding = AdvFinding(
                        scanner="csrf",
                        severity="Medium",
                        title="Missing CSRF Token",
                        description=(
                            f"A POST form on {page_url} does not appear to "
                            f"have CSRF protection. This could allow "
                            f"cross-site request forgery attacks."
                        ),
                        evidence=f"Form found without CSRF token on {page_url}",
                        recommendation=(
                            "Add CSRF tokens to all state-changing forms. "
                            "Use framework-provided CSRF protection "
                            "(e.g., Django's {% csrf_token %}, "
                            "Rails' authenticity_token)."
                        ),
                    )
                    result.findings.append(finding)
                    self._report(finding)
                    self._log(
                        f"  FOUND: POST form without CSRF token on "
                        f"{page_url}", "warning",
                    )

        result.forms_found = forms_found
        self._log(
            f"  CSRF scan complete. Found {forms_found} forms, "
            f"{forms_without_csrf} without CSRF protection.", "info",
        )

    # ── Open Redirect Scanner ─────────────────────────────────────────

    def _scan_open_redirect(self, url: str, result: AdvScanResult):
        """Test for open redirect vulnerabilities."""
        parsed = urllib.parse.urlparse(url)
        tested = 0

        for param in self.REDIRECT_PARAMS:
            if self._stopped():
                break

            for payload in self.REDIRECT_PAYLOADS:
                if self._stopped():
                    break

                query = urllib.parse.urlencode({param: payload})
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                tested += 1

                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    req = urllib.request.Request(test_url, method="GET")
                    req.add_header(
                        "User-Agent",
                        "Mozilla/5.0 AndyVulnScanner/1.0",
                    )

                    # Don't follow redirects
                    https_handler = urllib.request.HTTPSHandler(context=ctx)
                    opener = urllib.request.build_opener(
                        https_handler, _NoRedirectHandler(),
                    )
                    resp = opener.open(req, timeout=self.timeout)
                    location = resp.headers.get("Location", "")
                    resp.close()

                    if location and (
                        "evil.com" in location
                        or location.startswith("//evil.com")
                    ):
                        finding = AdvFinding(
                            scanner="redirect",
                            severity="Medium",
                            title="Open Redirect Vulnerability",
                            description=(
                                f"Open redirect found via parameter "
                                f"'{param}'. The server redirects to "
                                f"an external domain without validation."
                            ),
                            evidence=f"Redirects to: {location[:200]}",
                            payload=payload,
                            parameter=param,
                            recommendation=(
                                "Validate redirect URLs against a whitelist "
                                "of allowed domains. Never redirect to "
                                "user-supplied URLs without validation."
                            ),
                        )
                        result.findings.append(finding)
                        self._report(finding)
                        self._log(
                            f"  FOUND: Open redirect via '{param}' "
                            f"-> {location[:80]}", "error",
                        )
                        break

                except urllib.error.HTTPError as e:
                    location = e.headers.get("Location", "")
                    if location and (
                        "evil.com" in location
                        or location.startswith("//evil.com")
                    ):
                        finding = AdvFinding(
                            scanner="redirect",
                            severity="Medium",
                            title="Open Redirect Vulnerability",
                            description=(
                                f"Open redirect found via parameter "
                                f"'{param}'. Server returned {e.code} with "
                                f"redirect to external domain."
                            ),
                            evidence=f"Redirects to: {location[:200]}",
                            payload=payload,
                            parameter=param,
                            recommendation=(
                                "Validate redirect URLs against a whitelist."
                            ),
                        )
                        result.findings.append(finding)
                        self._report(finding)
                        self._log(
                            f"  FOUND: Open redirect via '{param}' "
                            f"-> {location[:80]}", "error",
                        )
                        break
                except Exception:
                    continue

        self._log(
            f"  Open redirect scan complete. Tested {tested} payloads.", "info",
        )

    # ── CORS Misconfiguration Scanner ─────────────────────────────────

    def _scan_cors(self, url: str, result: AdvScanResult):
        """Test for CORS misconfiguration."""
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            url.replace("://", "://evil."),
        ]

        for origin in test_origins:
            if self._stopped():
                break

            headers = {"Origin": origin}
            status, resp_headers, _ = self._make_request(
                url, headers=headers,
            )

            if status == 0:
                continue

            acao = resp_headers.get("Access-Control-Allow-Origin", "")
            acac = resp_headers.get(
                "Access-Control-Allow-Credentials", "",
            )

            if acao == "*":
                severity = "High" if acac.lower() == "true" else "Medium"
                finding = AdvFinding(
                    scanner="cors",
                    severity=severity,
                    title="CORS Wildcard Origin",
                    description=(
                        "The server allows requests from any origin "
                        "(Access-Control-Allow-Origin: *). "
                        + (
                            "Combined with Allow-Credentials: true, "
                            "this is a critical security issue."
                            if acac.lower() == "true"
                            else "This may expose sensitive data to "
                            "unauthorized origins."
                        )
                    ),
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    recommendation=(
                        "Restrict Access-Control-Allow-Origin to specific "
                        "trusted domains. Never use wildcard with "
                        "Allow-Credentials: true."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  FOUND: CORS wildcard origin"
                    f"{' with credentials!' if acac.lower() == 'true' else ''}",
                    "warning",
                )
                break

            if acao == origin and origin != url:
                severity = "High" if acac.lower() == "true" else "Medium"
                finding = AdvFinding(
                    scanner="cors",
                    severity=severity,
                    title="CORS Origin Reflection",
                    description=(
                        f"The server reflects the Origin header value "
                        f"'{origin}' in Access-Control-Allow-Origin. "
                        f"This means any origin can access the API."
                    ),
                    evidence=(
                        f"Origin sent: {origin}, ACAO: {acao}, ACAC: {acac}"
                    ),
                    recommendation=(
                        "Do not reflect the Origin header. Use a whitelist "
                        "of trusted origins instead."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  FOUND: CORS origin reflection for '{origin}'",
                    "error",
                )
                break

            if acao == "null":
                finding = AdvFinding(
                    scanner="cors",
                    severity="Medium",
                    title="CORS Null Origin Allowed",
                    description=(
                        "The server allows the 'null' origin. Sandboxed "
                        "iframes and local files send 'null' as their "
                        "origin, enabling potential abuse."
                    ),
                    evidence=f"ACAO: null, ACAC: {acac}",
                    recommendation=(
                        "Do not allow 'null' as a trusted origin. "
                        "Use specific domain whitelist."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log("  FOUND: CORS allows null origin", "warning")
                break

        if not any(f.scanner == "cors" for f in result.findings):
            self._log("  No CORS misconfiguration found.", "success")

        self._log("  CORS scan complete.", "info")

    # ── Cookie Security Scanner ───────────────────────────────────────

    def _scan_cookies(self, url: str, result: AdvScanResult):
        """Check cookie security flags."""
        status, raw_headers, _ = self._make_request_raw(url)
        if status == 0:
            self._log("  Could not reach target.", "error")
            return

        # Get all Set-Cookie headers (use get_all to avoid dict collapse)
        cookies_found = []
        if hasattr(raw_headers, "get_all"):
            cookies_found = raw_headers.get_all("Set-Cookie") or []
        else:
            for key, value in raw_headers.items():
                if key.lower() == "set-cookie":
                    cookies_found.append(value)

        if not cookies_found:
            self._log("  No cookies found in response.", "info")
            return

        self._log(f"  Found {len(cookies_found)} cookie(s).", "info")

        for cookie_str in cookies_found:
            cookie_name = cookie_str.split("=")[0].strip()
            cookie_lower = cookie_str.lower()

            # Check HttpOnly flag
            if "httponly" not in cookie_lower:
                finding = AdvFinding(
                    scanner="cookie",
                    severity="Medium",
                    title=f"Cookie Missing HttpOnly: {cookie_name}",
                    description=(
                        f"Cookie '{cookie_name}' does not have the HttpOnly "
                        f"flag. It can be accessed via JavaScript, making "
                        f"it vulnerable to XSS-based cookie theft."
                    ),
                    evidence=cookie_str[:200],
                    recommendation=(
                        "Add the HttpOnly flag to all session and "
                        "authentication cookies."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  FOUND: '{cookie_name}' missing HttpOnly", "warning",
                )

            # Check Secure flag
            if "secure" not in cookie_lower:
                finding = AdvFinding(
                    scanner="cookie",
                    severity="Medium",
                    title=f"Cookie Missing Secure Flag: {cookie_name}",
                    description=(
                        f"Cookie '{cookie_name}' does not have the Secure "
                        f"flag. It may be sent over unencrypted HTTP "
                        f"connections."
                    ),
                    evidence=cookie_str[:200],
                    recommendation=(
                        "Add the Secure flag to ensure cookies are only "
                        "sent over HTTPS connections."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  FOUND: '{cookie_name}' missing Secure flag",
                    "warning",
                )

            # Check SameSite attribute
            if "samesite" not in cookie_lower:
                finding = AdvFinding(
                    scanner="cookie",
                    severity="Low",
                    title=f"Cookie Missing SameSite: {cookie_name}",
                    description=(
                        f"Cookie '{cookie_name}' does not have the SameSite "
                        f"attribute. This may make it susceptible to "
                        f"cross-site request forgery (CSRF) attacks."
                    ),
                    evidence=cookie_str[:200],
                    recommendation=(
                        "Add SameSite=Strict or SameSite=Lax attribute "
                        "to cookies to prevent CSRF attacks."
                    ),
                )
                result.findings.append(finding)
                self._report(finding)
                self._log(
                    f"  FOUND: '{cookie_name}' missing SameSite", "info",
                )

        self._log("  Cookie security scan complete.", "info")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTP handler that does not follow redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Do not follow redirects; raise instead."""
        raise urllib.error.HTTPError(
            newurl, code, msg, headers, fp,
        )
