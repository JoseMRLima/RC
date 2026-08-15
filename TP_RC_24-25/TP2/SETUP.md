# SETUP — RC TP2 Packet Sniffer

Instruções de instalação, configuração e utilização.

---

## Instalação

### Requisitos

- Python 3.10+
- Permissões de root / administrador

### Dependências

```bash
pip install -r requirements.txt
```

`requirements.txt` contém:
```
scapy>=2.5.0
```

---

## Descobrir interfaces disponíveis

```bash
# Linux
ip link show
# ou
ifconfig -a
```

---

## Utilização básica

```bash
sudo python3 sniffer/main.py -i <interface> [opções]
```

### Todas as opções

| Flag | Descrição | Exemplo |
|------|-----------|---------|
| `-i`, `--interface` | Interface a escutar (**obrigatório**) | `eth0`, `wlan0` |
| `-p`, `--protocol` | Filtrar por protocolo | `ARP`, `ICMP`, `TCP`, `DNS` |
| `--ip` | Filtrar por endereço IP (src ou dst) | `192.168.1.1` |
| `--mac` | Filtrar por endereço MAC (src ou dst) | `aa:bb:cc:dd:ee:ff` |
| `--port` | Filtrar por porta (src ou dst) | `80`, `53` |
| `--bpf` | Filtro BPF personalizado | `'tcp port 80'` |
| `-n`, `--count` | Nº de pacotes a capturar (0 = infinito) | `100` |
| `--log` | Ficheiro de log (`.json`, `.csv`, `.txt`) | `logs/cap.json` |
| `--no-live` | Só log em ficheiro, sem output na consola | — |
| `--timeout` | Tempo máximo de captura em segundos | `60` |
| `--stats-interval` | Stats periódicas a cada N segundos | `10` |

---

## Exemplos de uso

### Captura simples na consola
```bash
sudo python3 sniffer/main.py -i eth0
```

### Só tráfego ICMP, guardar em JSON
```bash
sudo python3 sniffer/main.py -i eth0 -p ICMP --log logs/icmp.json
```

### Filtrar por IP e guardar em CSV
```bash
sudo python3 sniffer/main.py -i eth0 --ip 192.168.1.1 --log logs/host.csv
```

### Filtrar por porta (HTTP)
```bash
sudo python3 sniffer/main.py -i eth0 --port 80 --log logs/http.txt
```

### Filtro BPF (só tráfego TCP porta 80)
```bash
sudo python3 sniffer/main.py -i eth0 --bpf "tcp port 80"
```

### Só log em ficheiro, sem output na consola
```bash
sudo python3 sniffer/main.py -i eth0 --no-live --log logs/captura.json
```

### Captura limitada a 200 pacotes e 30 segundos
```bash
sudo python3 sniffer/main.py -i eth0 -n 200 --timeout 30
```

### Stats periódicas a cada 10 segundos (extra)
```bash
sudo python3 sniffer/main.py -i eth0 --stats-interval 10
```

---

## Correr no CORE (emulador)

### Topologia

Carregar o ficheiro `core_topology/TP2.imn` no emulador CORE.

```
n1 (PC)                 n2 (router)        n3        n5        n6 (host)
10.0.0.20/24   ───────  10.0.0.1/24                  ────────  10.0.5.10/24
2001:0::20/64           2001:0::1/64                            2001:5::10/64
```

### Iniciar o sniffer num nó

1. Clica com o botão direito no nó onde pretendes sniffar (ex: **n1**) → **Terminal**.
2. Dentro do terminal do nó:

```bash
cd /path/to/sniffer
python3 main.py -i eth0 --log /tmp/captura.json
```

3. Para a captura com `Ctrl+C` — o ficheiro é guardado automaticamente.

### Gerar tráfego entre nós

**ARP + ICMP** (ping ao gateway — gera ARP request/reply automaticamente):
```bash
# a partir de n1
ping -c 3 10.0.0.1
```

**ICMP cross-network** (n1 → n6, atravessa routers):
```bash
ping -c 5 10.0.5.10
```

**ICMPv6 + Neighbor Solicitation/Advertisement**:
```bash
ping6 -c 5 2001:0::1
```

**TCP** (abrir terminal em n6 e n1):
```bash
# n6:
nc -l -p 9000
# n1:
nc 10.0.5.10 9000
```

**UDP**:
```bash
# n6:
nc -u -l -p 5000
# n1:
echo "teste UDP" | nc -u 10.0.5.10 5000
```

**HTTP**:
```bash
# n6:
python3 -m http.server 80
# n1:
wget http://10.0.5.10/ -q -O /dev/null
```

> **Nota:** DNS e DHCP requerem servidores dedicados. Na topologia CORE os endereços são atribuídos estaticamente, pelo que estes protocolos devem ser testados na interface real do PC.

---

## Correr no PC (interface real)

```bash
# Listar interfaces
ip link show

# Captura geral na interface Wi-Fi
sudo python3 sniffer/main.py -i wlan0 --log logs/captura_real.json

# Só DNS
sudo python3 sniffer/main.py -i wlan0 --port 53

# Só HTTP
sudo python3 sniffer/main.py -i wlan0 --port 80

# DHCP (porta 67/68)
sudo python3 sniffer/main.py -i wlan0 -p DHCP

# Com stats periódicas e log
sudo python3 sniffer/main.py -i wlan0 --stats-interval 10 --log logs/real.json
```

> Requer permissões de root.

---

## Output na consola

Cada linha tem o formato:

```
[  N] TIMESTAMP       IFACE     PROTOCOLO   SRC:PORT             →  DST:PORT              SIZE   RESUMO
[   1] 2026-04-24 15:01:02.311  eth0      ICMP        10.0.0.20               → 10.0.5.10              98B  ICMP echo request id=1 seq=1
[   2] 2026-04-24 15:01:02.415  eth0      ICMP        10.0.5.10               → 10.0.0.20              98B  ICMP echo reply id=1 seq=1  [RTT=1.042ms]
```

Eventos TCP são destacados a verde por baixo da linha:
```
[  42] ...  TCP   10.0.0.20:54321  → 10.0.5.10:80   ...
         ↳ TCP SYN — nova ligação 10.0.0.20:54321 → 10.0.5.10:80
```

---

## Estatísticas no final da captura

Ao parar com `Ctrl+C`:

```
────────────────────────────────────────────────────────────
  Total de pacotes : 47
  Total de bytes   : 5120
  Duração          : 23.4s
  Taxa             : 2.0 pkt/s  |  0.2 KB/s
  Protocolos:
    ICMP           23 pacotes  (48.9%)  █████████
    TCP            12 pacotes  (25.5%)  █████
    ARP             8 pacotes  (17.0%)  ███
    HTTP            4 pacotes   (8.5%)  █

  RTT ICMP  min=0.812ms  avg=1.204ms  max=2.341ms  amostras=5

  Fluxos TCP:
    Origem                 Destino                Estado         Pkts    Bytes
    ──────────────────────────────────────────────────────────────────────────────
    10.0.0.20:54321        10.0.5.10:80           ESTABLISHED      12     5120
────────────────────────────────────────────────────────────
[INFO] Log guardado em: logs/captura.json
```
