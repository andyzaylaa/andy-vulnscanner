"""Port scanning module for VulnScanner."""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class PortResult:
    """Result of a single port scan."""

    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class ScanResult:
    """Result of a complete scan."""

    target: str
    ip_address: str = ""
    hostname: str = ""
    ports: list[PortResult] = field(default_factory=list)
    os_hint: str = ""
    scan_time: float = 0.0
    vulnerabilities: list[dict] = field(default_factory=list)


class PortScanner:
    """TCP port scanner with threading support."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8080,
        8443, 8888, 9090, 27017,
    ]

    WELL_KNOWN_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCbind",
        135: "MSRPC",
        139: "NetBIOS-SSN",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5985: "WinRM",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        8888: "HTTP-Alt",
        9090: "Web-Console",
        27017: "MongoDB",
    }

    def __init__(
        self,
        timeout: float = 1.5,
        max_threads: int = 100,
        on_port_scanned: Optional[Callable] = None,
        on_progress: Optional[Callable] = None,
    ):
        self.timeout = timeout
        self.max_threads = max_threads
        self.on_port_scanned = on_port_scanned
        self.on_progress = on_progress
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the scanner to stop."""
        self._stop_event.set()

    def reset(self) -> None:
        """Reset the stop signal."""
        self._stop_event.clear()

    def resolve_target(self, target: str) -> tuple[str, str]:
        """Resolve target to IP address and hostname."""
        try:
            ip_address = socket.gethostbyname(target)
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, socket.gaierror):
                hostname = target if target != ip_address else ""
            return ip_address, hostname
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{target}': {e}") from e

    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan a single port on the target IP."""
        if self._stop_event.is_set():
            return PortResult(port=port, state="filtered")

        result = PortResult(port=port, state="closed")
        result.service = self.WELL_KNOWN_SERVICES.get(port, "unknown")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            conn_result = sock.connect_ex((ip, port))

            if conn_result == 0:
                result.state = "open"
                # Try to grab the banner
                try:
                    sock.settimeout(2.0)
                    # Send a probe for HTTP services
                    if port in (80, 8080, 8443, 8888, 9090, 443):
                        sock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
                    elif port == 22:
                        pass  # SSH sends banner automatically
                    else:
                        sock.send(b"\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                    result.banner = banner[:200]  # Limit banner length
                    result.version = self._extract_version(banner, port)
                except (socket.timeout, OSError):
                    pass
            sock.close()
        except (socket.timeout, OSError):
            result.state = "filtered"

        return result

    def _extract_version(self, banner: str, port: int) -> str:
        """Extract version info from a banner string."""
        if not banner:
            return ""

        # SSH version extraction
        if port == 22 and banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) >= 3:
                return parts[2].split(" ")[0]
            return banner

        # HTTP Server header
        if "Server:" in banner:
            for line in banner.split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()

        # FTP banner
        if port == 21 and ("FTP" in banner.upper() or "220" in banner):
            return banner.replace("220 ", "").strip()[:80]

        # SMTP banner
        if port == 25 and "220" in banner:
            return banner.replace("220 ", "").strip()[:80]

        # Generic: return first line
        first_line = banner.split("\n")[0].strip()
        return first_line[:80] if first_line else ""

    def scan(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        scan_type: str = "common",
    ) -> ScanResult:
        """
        Scan a target for open ports.

        Args:
            target: IP address or hostname to scan.
            ports: Specific list of ports to scan.
            scan_type: 'common' for common ports, 'full' for 1-65535,
                       'custom' to use the ports parameter.
        """
        self.reset()
        ip_address, hostname = self.resolve_target(target)

        result = ScanResult(
            target=target,
            ip_address=ip_address,
            hostname=hostname,
        )

        if scan_type == "full":
            port_list = list(range(1, 65536))
        elif scan_type == "custom" and ports:
            port_list = ports
        else:
            port_list = self.COMMON_PORTS

        total_ports = len(port_list)
        scanned = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip_address, port): port
                for port in port_list
            }

            for future in as_completed(futures):
                if self._stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                port_result = future.result()
                scanned += 1

                if port_result.state == "open":
                    result.ports.append(port_result)
                    if self.on_port_scanned:
                        self.on_port_scanned(port_result)

                if self.on_progress:
                    self.on_progress(scanned, total_ports)

        # Sort open ports by port number
        result.ports.sort(key=lambda p: p.port)
        return result
