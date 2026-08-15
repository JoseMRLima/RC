#!/usr/bin/env python3
"""
RC TP2 — Packet Sniffer
Redes de Computadores 2025/2026 — Universidade do Minho
"""

import argparse
import sys
from capture import start_capture
from logger import Logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="RC TP2 — Packet Sniffer",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Interface de rede a escutar (ex: eth0, wlan0)"
    )
    parser.add_argument(
        "-p", "--protocol",
        default=None,
        help="Filtrar por protocolo (ex: ARP, ICMP, TCP, UDP, DNS, DHCP, HTTP)"
    )
    parser.add_argument(
        "--ip",
        default=None,
        help="Filtrar por endereço IP (origem ou destino)"
    )
    parser.add_argument(
        "--mac",
        default=None,
        help="Filtrar por endereço MAC (origem ou destino)"
    )
    parser.add_argument(
        "--bpf",
        default=None,
        help="Filtro BPF personalizado (ex: 'tcp port 80')"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Filtrar por porta (origem ou destino)"
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=0,
        help="Número de pacotes a capturar (0 = infinito)"
    )
    parser.add_argument(
        "--log",
        default=None,
        help="Ficheiro de log (ex: captura.json). Suporta .txt, .csv, .json"
    )
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="Desativar output na consola (apenas log em ficheiro)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Modo verbose: mostra timestamp completo, MACs, interface e tamanho (padrão: tempo relativo)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Tempo máximo de captura em segundos"
    )
    parser.add_argument(
        "--stats-interval",
        type=int,
        default=None,
        metavar="SEG",
        help="Mostrar estatísticas periódicas a cada N segundos (ex: 10)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    logger = Logger(
        logfile=args.log,
        live=not args.no_live,
        verbose=args.verbose,
    )

    stats_iv = getattr(args, "stats_interval", None)
    mode_str = "verbose (timestamp completo)" if args.verbose else "simples (tempo relativo)"
    print(f"""
╔══════════════════════════════════════════╗
║        RC TP2 — Packet Sniffer           ║
║   Redes de Computadores 2025/2026        ║
╚══════════════════════════════════════════╝
  Interface     : {args.interface}
  Protocolo     : {args.protocol or 'Todos'}
  Filtro IP     : {args.ip or '—'}
  Filtro MAC    : {args.mac or '—'}
  Filtro Port   : {args.port or '—'}
  Filtro BPF    : {args.bpf or '—'}
  Log file      : {args.log or '—'}
  Live mode     : {'Não' if args.no_live else 'Sim'}
  Modo output   : {mode_str}
  Stats intervalo: {f'{stats_iv}s' if stats_iv else '—'}
  [Extras] RTT ICMP + TCP flow tracking activos
""")

    try:
        start_capture(
            iface=args.interface,
            protocol_filter=args.protocol,
            ip_filter=args.ip,
            mac_filter=args.mac,
            bpf_filter=args.bpf,
            port_filter=args.port,
            count=args.count,
            timeout=args.timeout,
            logger=logger,
            stats_interval=getattr(args, "stats_interval", None),
        )
    except PermissionError:
        print("[ERRO] Permissões insuficientes. Corre com sudo.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Captura terminada pelo utilizador.")
    finally:
        logger.close()


if __name__ == "__main__":
    main()