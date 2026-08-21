"""
logger.py — Output na consola (live) e persistência em ficheiro (.txt/.csv/.json)
"""

from __future__ import annotations
from typing import Optional
import csv
import json
import time
from pathlib import Path


COLORS = {
    "ARP":    "\033[93m",
    "ICMP":   "\033[96m",
    "ICMPv6": "\033[96m",
    "DNS":    "\033[95m",
    "DHCP":   "\033[94m",
    "TCP":    "\033[92m",
    "HTTP":   "\033[32m",
    "UDP":    "\033[33m",
    "IPv4":   "\033[37m",
    "IPv6":   "\033[37m",
    "RESET":  "\033[0m",
}

FIELDS = ["timestamp", "interface", "protocol", "src_mac", "dst_mac", "src_ip", "dst_ip",
          "src_port", "dst_port", "size", "summary"]


class Logger:
    def __init__(self, logfile: Optional[str], live: bool, verbose: bool = False):
        self.live = live
        self.verbose = verbose
        self.logfile = logfile
        self._file = None
        self._csv_writer = None
        self._count = 0
        self._first_json = True
        self._stats: dict = {}
        self._total_bytes = 0
        self._start_time = time.time()
        self._rtt_stats: dict = {}
        self._flow_summary: str = ""

        if logfile:
            Path(logfile).parent.mkdir(parents=True, exist_ok=True)
            ext = Path(logfile).suffix.lower()
            self._ext = ext
            self._file = open(logfile, "w", encoding="utf-8", newline="")

            if ext == ".csv":
                self._csv_writer = csv.DictWriter(self._file, fieldnames=FIELDS)
                self._csv_writer.writeheader()
                self._file.flush()
            elif ext == ".txt":
                self._file.write("# RC TP2 — Packet Sniffer Log\n")
                self._file.write("-" * 120 + "\n")
                self._file.flush()
            elif ext == ".json":
                self._file.write("[\n")
                self._file.flush()

    def log(self, info: dict):
        self._count += 1
        info["#"] = self._count

        proto = info["protocol"].split()[0]
        self._stats[proto] = self._stats.get(proto, 0) + 1
        self._total_bytes += info.get("size", 0)

        if self.live:
            if self.verbose:
                self._print_verbose(info)
            else:
                self._print_simple(info)
        if self._file:
            self._write_file(info)

    def _print_simple(self, info: dict):
        """Modo simples: tempo relativo, só o essencial."""
        proto = info["protocol"].split()[0]
        color = next((v for k, v in COLORS.items() if k in proto), "")
        reset = COLORS["RESET"]

        elapsed = time.time() - self._start_time
        src = info.get("src_ip", "")
        dst = info.get("dst_ip", "")
        if info.get("src_port"):
            src = f"{src}:{info['src_port']}"
        if info.get("dst_port"):
            dst = f"{dst}:{info['dst_port']}"

        line = (
            f"{elapsed:>8.3f}s  "
            f"{color}{proto:<8}{reset}  "
            f"{src:<30} → {dst:<30}  "
            f"{info['summary']}"
        )
        print(line)
        if info.get("flow_event"):
            print(f"           \033[1;32m↳ {info['flow_event']}\033[0m")

    def _print_verbose(self, info: dict):
        """Modo verbose: tudo — igual ao comportamento anterior."""
        proto = info["protocol"].split()[0]
        color = next((v for k, v in COLORS.items() if k in proto), "")
        reset = COLORS["RESET"]
        src = f"{info['src_ip']}:{info['src_port']}" if info.get("src_port") else info.get("src_ip", "")
        dst = f"{info['dst_ip']}:{info['dst_port']}" if info.get("dst_port") else info.get("dst_ip", "")
        iface = info.get("interface", "")

        line = (
            f"[{self._count:>5}] {info['timestamp']}  "
            f"{iface:<8}  "
            f"{color}{info['protocol']:<10}{reset}  "
            f"{src:<24} → {dst:<24}  "
            f"{info['size']:>5}B  {info['summary']}"
        )
        if info.get("flow_event"):
            print(line)
            print(f"         \033[1;32m↳ {info['flow_event']}\033[0m")
        else:
            print(line)

    def _write_file(self, info: dict):
        # O ficheiro guarda sempre tudo, independentemente do modo live
        if self._ext == ".json":
            if not self._first_json:
                self._file.write(",\n")
            entry = {k: info.get(k, "") for k in FIELDS}
            self._file.write("  " + json.dumps(entry, ensure_ascii=False))
            self._file.flush()
            self._first_json = False
        elif self._ext == ".csv":
            self._csv_writer.writerow({k: info.get(k, "") for k in FIELDS})
            self._file.flush()
        elif self._ext == ".txt":
            src = f"{info['src_ip']}:{info['src_port']}" if info.get("src_port") else info.get("src_ip", "")
            dst = f"{info['dst_ip']}:{info['dst_port']}" if info.get("dst_port") else info.get("dst_ip", "")
            iface = info.get("interface", "")
            self._file.write(
                f"{info['timestamp']:<26} {iface:<8} {info['protocol']:<10} "
                f"{src:<18} {dst:<18} {info['size']:>6}B  {info['summary']}\n"
            )
            if info.get("flow_event"):
                self._file.write(f"  → {info['flow_event']}\n")
            self._file.flush()

    def set_rtt_stats(self, stats: dict):
        self._rtt_stats = stats

    def set_flow_summary(self, summary: str):
        self._flow_summary = summary

    def print_interim_stats(self):
        elapsed = max(time.time() - self._start_time, 0.001)
        print(f"\n  ── Stats [{elapsed:.0f}s] ── {self._count} pkt  "
              f"{self._total_bytes / 1024:.1f} KB  "
              f"{self._count / elapsed:.1f} pkt/s  "
              f"{self._total_bytes / elapsed / 1024:.1f} KB/s")

    def close(self):
        if self._file:
            if self._ext == ".json":
                self._file.write("\n]\n")
            self._file.close()

        elapsed = time.time() - self._start_time
        elapsed = max(elapsed, 0.001)

        print(f"\n{'─' * 60}")
        print(f"  Total de pacotes : {self._count}")
        print(f"  Total de bytes   : {self._total_bytes}")
        print(f"  Duração          : {elapsed:.1f}s")
        print(f"  Taxa             : {self._count / elapsed:.1f} pkt/s  |  {self._total_bytes / elapsed / 1024:.1f} KB/s")
        if self._stats:
            print(f"  Protocolos:")
            for proto, count in sorted(self._stats.items(), key=lambda x: -x[1]):
                pct = count / self._count * 100
                bar = "█" * int(pct / 5)
                print(f"    {proto:<12} {count:>5} pacotes  ({pct:5.1f}%)  {bar}")

        if self._rtt_stats:
            r = self._rtt_stats
            print(f"\n  RTT ICMP  min={r['min_ms']}ms  avg={r['avg_ms']}ms  "
                  f"max={r['max_ms']}ms  amostras={r['count']}")

        if self._flow_summary:
            print(f"\n  Fluxos TCP:\n{self._flow_summary}")

        print(f"{'─' * 60}")

        if self.logfile:
            print(f"[INFO] Log guardado em: {self.logfile}")