from collections import defaultdict

from scapy.all import ARP, DNS, IP, TCP, UDP, Ether, Raw, sniff
from scapy.layers.http import HTTPRequest

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


#####################################################################################################
# CONSTANTS
#####################################################################################################

CAPTURE_DURATION = 30  # seconds
SQL_INJECTION_PATTERNS = [
    "select",
    "union",
    "insert",
    "drop",
    "delete",
    "update",
    "or 1=1",
    "' or '",
    "--",
    "/*",
    "xp_",
]


#####################################################################################################
# CLASS
#####################################################################################################


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.attacks = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface for CAPTURE_DURATION seconds.
        """
        logger.info(f"Capturing traffic on interface '{self.interface}' for {CAPTURE_DURATION}s ...")
        self.packets = sniff(iface=self.interface, timeout=CAPTURE_DURATION)
        logger.info(f"Capture complete — {len(self.packets)} packets collected.")

    def sort_network_protocols(self) -> dict:
        """
        Sort and return all captured network protocols with their packet counts.

        :return: dict mapping protocol name -> packet count, sorted descending
        """
        protocol_counts = defaultdict(int)

        for pkt in self.packets:
            for layer_name in self._get_layer_names(pkt):
                protocol_counts[layer_name] += 1

        return dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True))

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packet count as a formatted string.

        :return: formatted string listing each protocol and its count
        """
        protocols = self.sort_network_protocols()
        lines = [f"  {proto}: {count} packet(s)" for proto, count in protocols.items()]
        return "\n".join(lines) if lines else "  No protocols captured."

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured packets and detect illegitimate traffic.
        Checks for SQL injection, ARP spoofing and port scanning.

        :param protocols: protocol filter hint (e.g. "tcp"), currently informational
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols:\n{all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.attacks = []
        self._detect_arp_spoofing()
        self._detect_sql_injection()
        self._detect_port_scan()

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return the analysis summary.

        :return: summary string
        """
        return self.summary

    # -----------------------------------------------------------------------------------------
    # PRIVATE
    # -----------------------------------------------------------------------------------------

    def _get_layer_names(self, pkt) -> list[str]:
        """Walk a packet and collect all layer names."""
        layers = []
        layer = pkt
        while layer:
            layers.append(layer.__class__.__name__)
            layer = layer.payload if layer.payload and layer.payload.__class__.__name__ != "NoPayload" else None
        return layers

    def _detect_arp_spoofing(self) -> None:
        """
        Detect ARP spoofing: same IP announced by multiple MAC addresses.
        """
        ip_to_mac: dict[str, set] = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                ip_to_mac[ip].add(mac)

        for ip, macs in ip_to_mac.items():
            if len(macs) > 1:
                self.attacks.append(
                    {
                        "type": "ARP Spoofing",
                        "protocol": "ARP",
                        "attacker_ip": ip,
                        "attacker_mac": ", ".join(macs),
                        "detail": f"IP {ip} announced by multiple MACs: {', '.join(macs)}",
                    }
                )
                logger.warning(f"[!] ARP Spoofing detected — IP {ip} claimed by {', '.join(macs)}")

    def _detect_sql_injection(self) -> None:
        """
        Detect SQL injection patterns in HTTP requests or raw TCP payloads.
        """
        for pkt in self.packets:
            payload = ""

            if pkt.haslayer(HTTPRequest):
                try:
                    payload = pkt[HTTPRequest].Path.decode(errors="replace").lower()
                    payload += " " + (pkt[Raw].load.decode(errors="replace").lower() if pkt.haslayer(Raw) else "")
                except Exception:
                    pass
            elif pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode(errors="replace").lower()
                except Exception:
                    pass

            if not payload:
                continue

            for pattern in SQL_INJECTION_PATTERNS:
                if pattern in payload:
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "unknown"
                    self.attacks.append(
                        {
                            "type": "SQL Injection",
                            "protocol": "HTTP/TCP",
                            "attacker_ip": src_ip,
                            "attacker_mac": src_mac,
                            "detail": f"Pattern '{pattern}' found in payload",
                        }
                    )
                    logger.warning(f"[!] SQL Injection detected from {src_ip} — pattern: '{pattern}'")
                    break

    def _detect_port_scan(self) -> None:
        """
        Detect port scanning: a single source hitting many distinct destination ports.
        Threshold: > 20 distinct ports contacted in the capture.
        """
        PORT_SCAN_THRESHOLD = 20
        src_ports: dict[str, set] = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_port = pkt[TCP].dport
                src_ports[src_ip].add(dst_port)

        for src_ip, ports in src_ports.items():
            if len(ports) > PORT_SCAN_THRESHOLD:
                src_mac = "unknown"
                for pkt in self.packets:
                    if pkt.haslayer(IP) and pkt[IP].src == src_ip and pkt.haslayer(Ether):
                        src_mac = pkt[Ether].src
                        break
                self.attacks.append(
                    {
                        "type": "Port Scan",
                        "protocol": "TCP",
                        "attacker_ip": src_ip,
                        "attacker_mac": src_mac,
                        "detail": f"{len(ports)} distinct ports contacted",
                    }
                )
                logger.warning(f"[!] Port scan detected from {src_ip} — {len(ports)} ports targeted")

    def _gen_summary(self) -> str:
        """
        Generate a human-readable analysis summary.

        :return: summary string
        """
        lines = ["=" * 60, "NETWORK CAPTURE ANALYSIS SUMMARY", "=" * 60, ""]

        # Protocol statistics
        protocols = self.sort_network_protocols()
        lines.append(f"Total packets captured : {len(self.packets)}")
        lines.append(f"Distinct protocols     : {len(protocols)}")
        lines.append("")
        lines.append("Protocol breakdown:")
        for proto, count in protocols.items():
            lines.append(f"  {proto:<20} {count} packet(s)")

        lines.append("")

        # Attack summary
        if self.attacks:
            lines.append(f"[!] {len(self.attacks)} attack(s) detected:")
            for atk in self.attacks:
                lines.append(f"  - {atk['type']}")
                lines.append(f"    Protocol  : {atk['protocol']}")
                lines.append(f"    Source IP : {atk['attacker_ip']}")
                lines.append(f"    Source MAC: {atk['attacker_mac']}")
                lines.append(f"    Detail    : {atk['detail']}")
        else:
            lines.append("[OK] No attacks detected — all traffic looks legitimate.")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
