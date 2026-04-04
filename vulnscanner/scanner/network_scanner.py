"""Network Sniffer module for Andy VulnScanner.

Captures and analyzes live network packets using raw sockets.
Requires root/sudo privileges on Kali Linux.
"""

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class PacketInfo:
    """Represents a captured network packet."""

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    info: str = ""
    raw_data: bytes = b""


@dataclass
class NetworkScanResult:
    """Result of a network capture session."""

    interface: str
    packets: list[PacketInfo] = field(default_factory=list)
    total_packets: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    unique_ips: set[str] = field(default_factory=set)
    capture_time: float = 0.0
    arp_packets: int = 0
    dns_packets: int = 0
    http_packets: int = 0


class NetworkSniffer:
    """Capture and analyze network packets using raw sockets."""

    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    def __init__(
        self,
        on_packet: Optional[Callable[[PacketInfo], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
        max_packets: int = 500,
        duration: int = 30,
    ):
        self.on_packet = on_packet
        self.on_log = on_log
        self.max_packets = max_packets
        self.duration = duration
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    def stop(self):
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def reset(self):
        self._stop_event.clear()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    def _log(self, msg: str, level: str = "info"):
        if self.on_log:
            self.on_log(msg, level)

    # ── Main capture ─────────────────────────────────────────────────

    def capture(self, interface: str = "any") -> NetworkScanResult:
        """Start capturing packets."""
        self.reset()
        result = NetworkScanResult(interface=interface)
        start_time = time.time()

        self._log(f"  Starting packet capture (max {self.max_packets} packets, "
                  f"{self.duration}s timeout)...", "info")
        self._log(f"  Interface: {interface}", "info")
        self._log("  Note: Requires root/sudo privileges.", "warning")

        try:
            # Create raw socket
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003),
            )
            self._sock.settimeout(1.0)

            if interface != "any":
                self._sock.bind((interface, 0))

            packet_count = 0
            while not self._stopped():
                # Check limits
                if packet_count >= self.max_packets:
                    self._log(
                        f"\n  Reached max packet limit ({self.max_packets}).",
                        "warning",
                    )
                    break
                elapsed = time.time() - start_time
                if elapsed >= self.duration:
                    self._log(
                        f"\n  Capture duration reached ({self.duration}s).",
                        "info",
                    )
                    break

                try:
                    raw_data, addr = self._sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                packet = self._parse_packet(raw_data)
                if packet:
                    packet_count += 1
                    result.packets.append(packet)
                    result.total_packets = packet_count
                    result.unique_ips.add(packet.src_ip)
                    result.unique_ips.add(packet.dst_ip)

                    # Track protocol stats
                    proto = packet.protocol
                    result.protocols[proto] = result.protocols.get(proto, 0) + 1

                    if proto == "ARP":
                        result.arp_packets += 1
                    elif packet.dst_port == 53 or packet.src_port == 53:
                        result.dns_packets += 1
                    elif packet.dst_port in (80, 8080) or packet.src_port in (80, 8080):
                        result.http_packets += 1

                    # Report packet
                    if self.on_packet:
                        self.on_packet(packet)

                    # Log every 50 packets
                    if packet_count % 50 == 0:
                        self._log(
                            f"  Captured {packet_count} packets...", "info",
                        )

        except PermissionError:
            self._log(
                "  ERROR: Root privileges required for packet capture!",
                "error",
            )
            self._log(
                "  Run the tool with: sudo python3 -m vulnscanner.main",
                "error",
            )
        except OSError as e:
            if not self._stopped():
                self._log(f"  Socket error: {e}", "error")
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

        result.capture_time = time.time() - start_time

        # Summary
        self._log("\n  Capture complete:", "success")
        self._log(f"    Total packets: {result.total_packets}", "info")
        self._log(f"    Unique IPs: {len(result.unique_ips)}", "info")
        self._log(f"    Duration: {result.capture_time:.1f}s", "info")
        for proto, count in sorted(
            result.protocols.items(), key=lambda x: x[1], reverse=True,
        ):
            self._log(f"    {proto}: {count} packets", "info")

        return result

    # ── Packet parsing ───────────────────────────────────────────────

    def _parse_packet(self, raw_data: bytes) -> Optional[PacketInfo]:
        """Parse raw packet data."""
        if len(raw_data) < 14:
            return None

        # Ethernet header (14 bytes)
        eth_header = raw_data[:14]
        eth_proto = struct.unpack("!H", eth_header[12:14])[0]

        # ARP (0x0806)
        if eth_proto == 0x0806:
            return self._parse_arp(raw_data[14:])

        # IPv4 (0x0800)
        if eth_proto == 0x0800:
            return self._parse_ipv4(raw_data[14:])

        # IPv6 (0x86DD)
        if eth_proto == 0x86DD:
            return self._parse_ipv6(raw_data[14:])

        return None

    def _parse_arp(self, data: bytes) -> Optional[PacketInfo]:
        """Parse ARP packet."""
        if len(data) < 28:
            return None
        # ARP header
        opcode = struct.unpack("!H", data[6:8])[0]
        sender_ip = socket.inet_ntoa(data[14:18])
        target_ip = socket.inet_ntoa(data[24:28])
        op_str = "Request" if opcode == 1 else "Reply" if opcode == 2 else f"Op{opcode}"

        return PacketInfo(
            timestamp=time.time(),
            src_ip=sender_ip,
            dst_ip=target_ip,
            protocol="ARP",
            info=f"ARP {op_str}: Who has {target_ip}? Tell {sender_ip}",
            raw_data=data[:28],
        )

    def _parse_ipv4(self, data: bytes) -> Optional[PacketInfo]:
        """Parse IPv4 packet."""
        if len(data) < 20:
            return None

        # IP header
        version_ihl = data[0]
        ihl = (version_ihl & 0x0F) * 4
        total_length = struct.unpack("!H", data[2:4])[0]
        protocol = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])

        proto_name = self.PROTOCOL_MAP.get(protocol, f"Proto{protocol}")
        src_port = 0
        dst_port = 0
        info = ""

        # Parse transport layer
        transport_data = data[ihl:]

        if protocol == 6 and len(transport_data) >= 20:  # TCP
            src_port = struct.unpack("!H", transport_data[0:2])[0]
            dst_port = struct.unpack("!H", transport_data[2:4])[0]
            flags = transport_data[13]
            flag_str = self._tcp_flags(flags)
            info = f"TCP {src_port} -> {dst_port} [{flag_str}]"

        elif protocol == 17 and len(transport_data) >= 8:  # UDP
            src_port = struct.unpack("!H", transport_data[0:2])[0]
            dst_port = struct.unpack("!H", transport_data[2:4])[0]
            info = f"UDP {src_port} -> {dst_port}"

            # Check for DNS
            if src_port == 53 or dst_port == 53:
                dns_info = self._parse_dns_brief(transport_data[8:])
                if dns_info:
                    info = f"DNS {dns_info}"
                    proto_name = "DNS"

        elif protocol == 1 and len(transport_data) >= 8:  # ICMP
            icmp_type = transport_data[0]
            icmp_code = transport_data[1]
            icmp_types = {
                0: "Echo Reply", 3: "Dest Unreachable",
                8: "Echo Request", 11: "Time Exceeded",
            }
            type_str = icmp_types.get(icmp_type, f"Type {icmp_type}")
            info = f"ICMP {type_str} (code={icmp_code})"

        else:
            info = f"{proto_name} packet"

        return PacketInfo(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto_name,
            src_port=src_port,
            dst_port=dst_port,
            length=total_length,
            info=info,
            raw_data=data[:min(len(data), 128)],
        )

    def _parse_ipv6(self, data: bytes) -> Optional[PacketInfo]:
        """Parse IPv6 packet (basic)."""
        if len(data) < 40:
            return None

        next_header = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

        proto_name = self.PROTOCOL_MAP.get(next_header, f"IPv6-Proto{next_header}")
        info = f"IPv6 {proto_name}"

        return PacketInfo(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=f"IPv6/{proto_name}",
            info=info,
            raw_data=data[:min(len(data), 128)],
        )

    def _tcp_flags(self, flags: int) -> str:
        """Convert TCP flags byte to string."""
        flag_names = []
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x08:
            flag_names.append("PSH")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x20:
            flag_names.append("URG")
        return ",".join(flag_names) if flag_names else "NONE"

    def _parse_dns_brief(self, data: bytes) -> str:
        """Parse DNS packet for a brief summary."""
        if len(data) < 12:
            return ""
        flags = struct.unpack("!H", data[2:4])[0]
        is_response = bool(flags & 0x8000)
        _ = struct.unpack("!H", data[4:6])[0]  # qdcount

        # Try to parse the question name
        name = self._parse_dns_name(data, 12)
        direction = "Response" if is_response else "Query"
        return f"{direction}: {name}" if name else direction
    
    def _parse_dns_name(self, data: bytes, offset: int) -> str:
        """Parse a DNS domain name from packet data."""
        labels = []
        pos = offset
        max_jumps = 10
        jumps = 0
        while pos < len(data) and jumps < max_jumps:
            length = data[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:  # Pointer
                if pos + 1 >= len(data):
                    break
                ptr = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
                pos = ptr
                jumps += 1
                continue
            pos += 1
            if pos + length > len(data):
                break
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else ""
