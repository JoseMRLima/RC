from __future__ import annotations
"""
Identificação e análise de protocolos
Protocolos suportados: Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, DHCP, HTTP
"""

from datetime import datetime
from typing import Optional
from scapy.all import (
    Ether, ARP, IP, IPv6, ICMP,
    ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6TimeExceeded,
    ICMPv6ND_NS, ICMPv6ND_NA,
    TCP, UDP, DNS, DNSQR, DNSRR, BOOTP, DHCP, Raw,
)


def analyze_packet(pkt):
    """Analisa um pacote e devolve um dicionário com os campos relevantes"""
    info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "size": len(pkt),
        "protocol": "UNKNOWN",
        "src_mac": "",
        "dst_mac": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": "",
        "summary": "",
    }

    # --- Ethernet ---
    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    # --- ARP ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        info["protocol"] = "ARP"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        op = "request" if arp.op == 1 else "reply"
        info["summary"] = f"ARP {op}: who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 \
            else f"ARP reply: {arp.psrc} is at {arp.hwsrc}"
        return info

    # --- IPv4 base ---
    if pkt.haslayer(IP):
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst

    # --- IPv6 base ---
    if pkt.haslayer(IPv6):
        info["src_ip"] = pkt[IPv6].src
        info["dst_ip"] = pkt[IPv6].dst

    # --- ICMP (IPv4) ---
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info["protocol"] = "ICMP"
        type_map = {0: "echo reply", 8: "echo request", 3: "dest unreachable", 11: "time exceeded"}
        t = type_map.get(icmp.type, f"type={icmp.type}")
        icmp_id  = icmp.id  if hasattr(icmp, "id")  else 0
        icmp_seq = icmp.seq if hasattr(icmp, "seq") else 0
        info["icmp_type"] = icmp.type
        info["icmp_id"]   = icmp_id
        info["icmp_seq"]  = icmp_seq
        info["summary"] = f"ICMP {t} id={icmp_id} seq={icmp_seq}"
        return info

    # --- ICMPv6 ---
    if pkt.haslayer(ICMPv6EchoRequest):
        v6 = pkt[ICMPv6EchoRequest]
        info["protocol"] = "ICMPv6"
        info["icmp_type"] = 128
        info["icmp_id"]   = v6.id
        info["icmp_seq"]  = v6.seq
        info["summary"] = f"ICMPv6 echo request id={v6.id} seq={v6.seq}"
        return info

    if pkt.haslayer(ICMPv6EchoReply):
        v6 = pkt[ICMPv6EchoReply]
        info["protocol"] = "ICMPv6"
        info["icmp_type"] = 129
        info["icmp_id"]   = v6.id
        info["icmp_seq"]  = v6.seq
        info["summary"] = f"ICMPv6 echo reply id={v6.id} seq={v6.seq}"
        return info

    if pkt.haslayer(ICMPv6ND_NS):
        info["protocol"] = "ICMPv6"
        info["summary"] = f"ICMPv6 Neighbor Solicitation → {pkt[ICMPv6ND_NS].tgt}"
        return info

    if pkt.haslayer(ICMPv6ND_NA):
        info["protocol"] = "ICMPv6"
        info["summary"] = f"ICMPv6 Neighbor Advertisement: {pkt[ICMPv6ND_NA].tgt}"
        return info

    if pkt.haslayer(ICMPv6DestUnreach):
        info["protocol"] = "ICMPv6"
        info["summary"] = "ICMPv6 Destination Unreachable"
        return info

    if pkt.haslayer(ICMPv6TimeExceeded):
        info["protocol"] = "ICMPv6"
        info["summary"] = "ICMPv6 Time Exceeded"
        return info

    # --- DHCP ---
    if pkt.haslayer(DHCP):
        dhcp = pkt[DHCP]
        msg_types = {
            1: "Discover", 2: "Offer", 3: "Request",
            4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
        }
        msg_type_opt = next(
            (opt[1] for opt in dhcp.options if isinstance(opt, tuple) and opt[0] == "message-type"),
            None,
        )
        label = msg_types.get(msg_type_opt, f"type={msg_type_opt}")
        info["protocol"] = "DHCP"
        info["summary"] = f"DHCP {label}"
        if pkt.haslayer(BOOTP):
            info["src_ip"] = pkt[BOOTP].ciaddr or "0.0.0.0"
        return info

    # --- DNS ---
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        info["protocol"] = "DNS"
        if pkt.haslayer(UDP):
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
        if dns.qr == 0 and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 12: "PTR", 16: "TXT"}
            qtype = qtype_map.get(pkt[DNSQR].qtype, f"type={pkt[DNSQR].qtype}")
            info["summary"] = f"DNS query {qtype} {qname}"
        elif dns.qr == 1 and pkt.haslayer(DNSRR):
            rname = pkt[DNSRR].rrname.decode(errors="replace").rstrip(".")
            rdata = pkt[DNSRR].rdata
            if isinstance(rdata, bytes):
                try:
                    rdata = rdata.decode(errors="replace").rstrip(".")
                except Exception:
                    rdata = rdata.hex()
            info["summary"] = f"DNS response: {rname} → {rdata}"
        else:
            info["summary"] = "DNS"
        return info

    # --- UDP ---
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport
        info["protocol"] = "UDP"
        src_ip = info["src_ip"] or "?"
        dst_ip = info["dst_ip"] or "?"
        info["summary"] = f"UDP {src_ip}:{udp.sport} → {dst_ip}:{udp.dport}"
        return info

    # --- TCP / HTTP ---
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["tcp_flags_int"] = int(tcp.flags)
        flags = _tcp_flags(tcp.flags)
        src_ip = info["src_ip"] or "?"
        dst_ip = info["dst_ip"] or "?"

        # HTTP heurístico (porta 80/8080 ou payload com métodos HTTP)
        if (tcp.dport in (80, 8080) or tcp.sport in (80, 8080)) and pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="replace")
            http_info = _parse_http(payload)
            if http_info:
                info["protocol"] = "HTTP"
                info["summary"] = http_info
                return info

        # HTTP heurístico em qualquer porta (payload contém método HTTP)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode(errors="replace")
            http_info = _parse_http(payload)
            if http_info:
                info["protocol"] = "HTTP"
                info["summary"] = http_info
                return info

        info["protocol"] = "TCP"
        info["summary"] = f"TCP [{flags}] {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport}"
        return info
    
    

    # --- IPv4 genérico ---
    if pkt.haslayer(IP):
        info["protocol"] = f"IPv4 (proto={pkt[IP].proto})"
        info["summary"] = f"IPv4 {pkt[IP].src} → {pkt[IP].dst}"
        return info

    # --- IPv6 genérico ---
    if pkt.haslayer(IPv6):
        info["protocol"] = "IPv6"
        info["summary"] = f"IPv6 {info['src_ip']} → {info['dst_ip']}"
        return info

    # Ethernet genérico
    if pkt.haslayer(Ether):
        info["protocol"] = f"ETH (type=0x{pkt[Ether].type:04x})"
        info["summary"] = "Ethernet frame"
        return info

    return None


def _tcp_flags(flags) -> str:
    names = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    active = [name for bit, name in names.items() if int(flags) & bit]
    return "|".join(active) if active else str(flags)


def _parse_http(payload: str) -> Optional[str]:
    """Extrai informação relevante de um payload HTTP. Retorna None se não for HTTP."""
    first_line = payload.split("\r\n")[0] if "\r\n" in payload else payload[:100]
    parts = first_line.split(" ", 2)

    # Request: METHOD /path HTTP/1.x
    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT")
    if parts[0] in http_methods and len(parts) >= 2:
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "?"
        version = parts[2] if len(parts) > 2 else ""
        return f"HTTP {method} {path} {version}".strip()

    # Response: HTTP/1.x STATUS_CODE reason
    if parts[0].startswith("HTTP/") and len(parts) >= 2:
        version = parts[0]
        status = parts[1]
        reason = parts[2] if len(parts) > 2 else ""
        return f"HTTP {version} {status} {reason}".strip()

    return None
