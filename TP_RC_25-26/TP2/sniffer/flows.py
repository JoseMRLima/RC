"""
flows.py — Rastreamento de fluxos TCP (handshake e terminação)
"""

from __future__ import annotations
from threading import Lock
from datetime import datetime


# Estados de uma ligação TCP
_STATES = {
    "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT", "CLOSED",
}


class TCPFlow:
    __slots__ = ("src", "dst", "sport", "dport", "state", "started", "ended", "packets", "bytes")

    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.state = "SYN_SENT"
        self.started = datetime.now()
        self.ended = None
        self.packets = 0
        self.bytes = 0

    def key(self):
        return (self.src, self.dst, self.sport, self.dport)

    def canonical_key(self):
        a = (self.src, self.sport)
        b = (self.dst, self.dport)
        return (min(a, b), max(a, b))


class FlowTracker:
    """Rastreia o estado de ligações TCP."""

    def __init__(self):
        self._flows: dict[tuple, TCPFlow] = {}
        self._lock = Lock()

    def update(self, src_ip: str, dst_ip: str, sport: int, dport: int,
               flags_int: int, pkt_size: int) -> str | None:
        """
        Atualiza o estado da ligação e devolve uma string de evento se relevante,
        ou None caso contrário.
        """
        SYN = 0x02
        ACK = 0x10
        FIN = 0x01
        RST = 0x04

        fwd_key = (src_ip, dst_ip, sport, dport)
        rev_key = (dst_ip, src_ip, dport, sport)

        event = None
        with self._lock:
            # RST — fecha imediatamente
            if flags_int & RST:
                for k in (fwd_key, rev_key):
                    if k in self._flows:
                        self._flows[k].state = "CLOSED"
                        self._flows[k].ended = datetime.now()
                        event = f"TCP RST — ligação terminada ({src_ip}:{sport} ↔ {dst_ip}:{dport})"
                        del self._flows[k]
                        break
                return event

            # SYN sem ACK — início da ligação
            if (flags_int & SYN) and not (flags_int & ACK):
                if fwd_key not in self._flows and rev_key not in self._flows:
                    flow = TCPFlow(src_ip, dst_ip, sport, dport)
                    flow.packets = 1
                    flow.bytes = pkt_size
                    self._flows[fwd_key] = flow
                    event = f"TCP SYN — nova ligação {src_ip}:{sport} → {dst_ip}:{dport}"
                return event

            # SYN+ACK — servidor responde
            if (flags_int & SYN) and (flags_int & ACK):
                if rev_key in self._flows and self._flows[rev_key].state == "SYN_SENT":
                    self._flows[rev_key].state = "SYN_RCVD"
                    event = f"TCP SYN-ACK — {src_ip}:{sport} → {dst_ip}:{dport}"
                return event

            # ACK puro após SYN-ACK — ligação estabelecida
            if (flags_int & ACK) and not (flags_int & SYN) and not (flags_int & FIN):
                for k in (fwd_key, rev_key):
                    if k in self._flows and self._flows[k].state == "SYN_RCVD":
                        self._flows[k].state = "ESTABLISHED"
                        event = (f"TCP ESTABLISHED — {self._flows[k].src}:{self._flows[k].sport}"
                                 f" ↔ {self._flows[k].dst}:{self._flows[k].dport}")
                        break

            # FIN — início de terminação
            if flags_int & FIN:
                for k in (fwd_key, rev_key):
                    if k in self._flows and self._flows[k].state == "ESTABLISHED":
                        self._flows[k].state = "FIN_WAIT"
                        event = (f"TCP FIN — fecho de ligação "
                                 f"{self._flows[k].src}:{self._flows[k].sport}"
                                 f" ↔ {self._flows[k].dst}:{self._flows[k].dport}")
                        break

            # Contabiliza bytes/pacotes no fluxo activo
            for k in (fwd_key, rev_key):
                if k in self._flows:
                    self._flows[k].packets += 1
                    self._flows[k].bytes += pkt_size
                    break

        return event

    def active_flows(self) -> list[TCPFlow]:
        with self._lock:
            return list(self._flows.values())

    def summary(self) -> str:
        flows = self.active_flows()
        if not flows:
            return "  Sem fluxos TCP activos."
        lines = [f"  {'Origem':<22} {'Destino':<22} {'Estado':<14} {'Pkts':>6} {'Bytes':>8}"]
        lines.append("  " + "─" * 78)
        for f in flows:
            lines.append(
                f"  {f.src}:{f.sport:<6} {f.dst}:{f.dport:<6} "
                f"{f.state:<14} {f.packets:>6} {f.bytes:>8}"
            )
        return "\n".join(lines)
