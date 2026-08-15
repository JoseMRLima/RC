from __future__ import annotations
"""
Motor de captura de pacotes com Scapy
"""

import threading
import time
from typing import Optional
from scapy.all import sniff
from analyzer import analyze_packet
from rtt import RTTTracker
from flows import FlowTracker


def start_capture(
    iface: str,
    protocol_filter: Optional[str],
    ip_filter: Optional[str],
    mac_filter: Optional[str],
    bpf_filter: Optional[str],
    port_filter: Optional[int],
    count: int,
    timeout: Optional[int],
    logger,
    stats_interval: Optional[int] = None,
):
    """Inicia a captura de pacotes na interface indicada."""

    rtt_tracker = RTTTracker()
    flow_tracker = FlowTracker()

    def packet_callback(pkt):
        info = analyze_packet(pkt)
        if info is None:
            return

        info["interface"] = iface

        # Filtro por protocolo
        if protocol_filter:
            if protocol_filter.upper() not in info["protocol"].upper():
                return

        # Filtro por IP
        if ip_filter:
            if ip_filter not in (info.get("src_ip", ""), info.get("dst_ip", "")):
                return

        # Filtro por MAC
        if mac_filter:
            if mac_filter.lower() not in (
                info.get("src_mac", "").lower(),
                info.get("dst_mac", "").lower(),
            ):
                return

        # Filtro por porta
        if port_filter is not None:
            if port_filter not in (info.get("src_port", ""), info.get("dst_port", "")):
                return

        # RTT ICMP
        proto = info.get("protocol", "")
        icmp_type = info.get("icmp_type")
        if proto in ("ICMP", "ICMPv6") and icmp_type is not None:
            icmp_id  = info.get("icmp_id", 0)
            icmp_seq = info.get("icmp_seq", 0)
            src_ip   = info.get("src_ip", "")
            dst_ip   = info.get("dst_ip", "")
            # request: ICMP type 8 (IPv4) or 128 (IPv6)
            if icmp_type in (8, 128):
                rtt_tracker.record_request(src_ip, dst_ip, icmp_id, icmp_seq)
            # reply: ICMP type 0 (IPv4) or 129 (IPv6)
            elif icmp_type in (0, 129):
                rtt_ms = rtt_tracker.record_reply(src_ip, dst_ip, icmp_id, icmp_seq)
                if rtt_ms is not None:
                    info["summary"] += f"  [RTT={rtt_ms:.3f}ms]"

        # TCP flow tracking
        if proto == "TCP":
            flags_int = info.get("tcp_flags_int", 0)
            src_ip  = info.get("src_ip", "")
            dst_ip  = info.get("dst_ip", "")
            sport   = info.get("src_port", 0)
            dport   = info.get("dst_port", 0)
            event = flow_tracker.update(src_ip, dst_ip, sport, dport, flags_int, info.get("size", 0))
            if event:
                info["flow_event"] = event

        logger.log(info)

    # THREADS DE BACKGROUND (Alertas e Estatísticas)
    # Criamos o evento de paragem para todas as threads
    stop_event = threading.Event()

    # Detetor de Falhas Independente (Corre SEMPRE)
    def timeout_loop():
        while not stop_event.wait(1.0): # Verifica a cada 1 segundo
            timeouts = rtt_tracker.get_timeouts(timeout_sec=2.0)
            if timeouts:
                print(f"\n  \033[91m[ALERTA REDE]\033[0m {len(timeouts)} pacotes ICMP perdidos (Timeout > 2s)!")
                for key in timeouts:
                    src_ip, dst_ip, icmp_id, icmp_seq = key
                    print(f"    ↳ Ping: {src_ip} → {dst_ip} (id={icmp_id} seq={icmp_seq}) sem resposta.")
    
    # Inicia a thread dos alertas
    threading.Thread(target=timeout_loop, daemon=True).start()

    # Thread de stats periódicas (Só corre se o utilizador pedir)
    if stats_interval and stats_interval > 0:
        def stats_loop():
            while not stop_event.wait(stats_interval):
                logger.print_interim_stats()
                
                rtt_stats = rtt_tracker.stats()
                if rtt_stats:
                    print(f"\n  [RTT ICMP] min={rtt_stats['min_ms']}ms  "
                          f"avg={rtt_stats['avg_ms']}ms  "
                          f"max={rtt_stats['max_ms']}ms  "
                          f"amostras={rtt_stats['count']}")
                
                active = flow_tracker.active_flows()
                if active:
                    print(f"\n  [Fluxos TCP activos: {len(active)}]")
                    print(flow_tracker.summary())

        t = threading.Thread(target=stats_loop, daemon=True)
        t.start()
    

    try:
        sniff(
            iface=iface,
            prn=packet_callback,
            filter=bpf_filter or "",
            count=count,
            timeout=timeout,
            store=False,
        )
    finally:
        stop_event.set() 