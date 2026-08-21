"""
rtt.py — Rastreamento de RTT para ICMP echo request/reply
"""

from __future__ import annotations
import time
from threading import Lock


class RTTTracker:
    """Mede o RTT de pares ICMP echo request / echo reply."""

    def __init__(self):
        self._pending: dict[tuple, float] = {}
        self._lock = Lock()
        self._samples: list[float] = []

    def record_request(self, src_ip: str, dst_ip: str, icmp_id: int, seq: int):
        key = (src_ip, dst_ip, icmp_id, seq)
        with self._lock:
            self._pending[key] = time.perf_counter()

    def record_reply(self, src_ip: str, dst_ip: str, icmp_id: int, seq: int) -> float | None:
        key = (dst_ip, src_ip, icmp_id, seq)  # reply swaps src/dst
        with self._lock:
            sent_at = self._pending.pop(key, None)
        if sent_at is None:
            return None
        rtt_ms = (time.perf_counter() - sent_at) * 1000
        with self._lock:
            self._samples.append(rtt_ms)
        return rtt_ms

    def stats(self) -> dict:
        with self._lock:
            s = list(self._samples)
        if not s:
            return {}
        return {
            "count": len(s),
            "min_ms": round(min(s), 3),
            "max_ms": round(max(s), 3),
            "avg_ms": round(sum(s) / len(s), 3),
        }
    
    def get_timeouts(self, timeout_sec: float = 2.0) -> list[tuple]:
        """Verifica se há pacotes pendentes sem resposta há mais de 'timeout_sec' segundos."""
        now = time.perf_counter()
        timeouts = []
        with self._lock:
            # Transforma as chaves em lista para podermos apagar elementos em segurança
            for key, sent_at in list(self._pending.items()):
                if (now - sent_at) > timeout_sec:
                    timeouts.append(key)
                    # Removemos para não dar o mesmo alerta repetidamente nem gastar memória
                    del self._pending[key] 
        return timeouts
