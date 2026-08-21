# RC TP2 — Packet Sniffer
 
> Redes de Computadores 2025/2026 — Universidade do Minho  
> Grupo PL30
 
Packet Sniffer desenvolvido em Python com Scapy, capaz de capturar identificar, filtrar e registar tráfego de rede em tempo real — em ambiente emulado (CORE) e em interface real (Wi-Fi/Ethernet).
 


## Dependências
 
**Requisitos:**
- Python 3.10+
- Permissões de root/administrador (necessárias para captura de pacotes)

**Instalar dependências:**
 
```bash
pip install -r scapy>=2.5.0 //to review
```

## Como selecionar a interface de rede
 
Primeiro, lista as interfaces disponíveis:
 
```bash
ip link show
```
 
Exemplos de interfaces comuns:
 
| Interface | Contexto |
|-----------|----------|
| `eth0`    | Nó virtual no CORE |
| `wlo1`    | Wi-Fi no PC real (pode variar) |
| `lo`      | Loopback (não usar para captura) |
 
Passa a interface com a flag `-i`:
 
```bash
sudo python3 sniffer/main.py -i eth0
sudo python3 sniffer/main.py -i wlo1
```



## Como ativar filtros e funcionalidades
 
### Flags disponíveis
 
| Flag | Descrição | Exemplo |
|------|-----------|---------|
| `-i`, `--interface` | Interface a escutar (**obrigatório**) | `-i eth0` |
| `-p`, `--protocol` | Filtrar por protocolo | `-p ICMP` |
| `--ip` | Filtrar por endereço IP (src ou dst) | `--ip 10.0.5.10` |
| `--mac` | Filtrar por endereço MAC (src ou dst) | `--mac 00:00:00:aa:00:01` |
| `--port` | Filtrar por porta (src ou dst) | `--port 53` |
| `--bpf` | Filtro BPF arbitrário (passado ao libpcap) | `--bpf "tcp port 80"` |
| `-n`, `--count` | Nº de pacotes a capturar (0 = infinito) | `-n 10` |
| `--log` | Ficheiro de log (`.json`, `.csv`, `.txt`) | `--log logs/cap.json` |
| `--no-live` | Desativar output na consola (só ficheiro) | `--no-live` |
| `-v`, `--verbose` | Output detalhado: timestamp completo, MACs, tamanho | `-v` |
| `--timeout` | Tempo máximo de captura em segundos | `--timeout 30` |
| `--stats-interval` | Estatísticas periódicas a cada N segundos | `--stats-interval 10` |
 
### Exemplos de uso dos filtros
 
```bash
# Capturar só tráfego ICMP e guardar em JSON
sudo python3 sniffer/main.py -i eth0 -p ICMP --log logs/icmp.json
 
# Filtrar por endereço IP
sudo python3 sniffer/main.py -i eth0 --ip 10.0.5.10
 
# Filtrar por endereço MAC
sudo python3 sniffer/main.py -i eth0 --mac 00:00:00:aa:00:01
 
# Filtrar por porta (DNS)
sudo python3 sniffer/main.py -i wlo1 --port 53
 
# Filtro BPF personalizado
sudo python3 sniffer/main.py -i eth0 --bpf "tcp port 80"
 
# Combinar filtros: só ICMP do IP 10.0.5.10
sudo python3 sniffer/main.py -i eth0 -p ICMP --ip 10.0.5.10
 
# Capturar 10 pacotes e parar automaticamente
sudo python3 sniffer/main.py -i eth0 -p ICMP -n 10
 
# Modo verbose (timestamp completo + MACs + tamanho)
sudo python3 sniffer/main.py -i eth0 -v
 
# Só log em ficheiro, sem output na consola
sudo python3 sniffer/main.py -i eth0 --no-live --log logs/captura.json
 
# Estatísticas periódicas a cada 10 segundos
sudo python3 sniffer/main.py -i eth0 --stats-interval 10
```
 
### Modos de output na consola
 
**Modo simples (default)** — tempo relativo desde o início da captura:
```
   0.000s  ICMP      10.0.5.10              → 10.0.0.20              ICMP echo request id=1 seq=1
   0.002s  ICMP      10.0.0.20              → 10.0.5.10              ICMP echo reply id=1 seq=1  [RTT=2.1ms]
```
 
**Modo verbose (`-v`)** — timestamp completo com todos os campos:
```
[    1] 2026-05-04 23:34:08  eth0      ICMP        10.0.5.10  → 10.0.0.20   98B  ICMP echo request id=1 seq=1
[    2] 2026-05-04 23:34:08  eth0      ICMP        10.0.0.20  → 10.0.5.10   98B  ICMP echo reply id=1 seq=1  [RTT=2.1ms]
```
 
Nota: O ficheiro de log guarda sempre o formato completo, independentemente do modo de consola.
 



## Como Correr no CORE (Parte A)

### 1. Iniciar o Sniffer (No PcSniffer)

No nó **PcSniffer** corre o programa:

```bash
cd /media/sf_RC-TP-2526/TP2/sniffer
python3 main.py -i eth0 --log ../logs/captura.json
```

> Deixa este terminal aberto a correr durante os testes.



### 2. Gerar Tráfego (Interações entre PcSniffer e SrvWeb)

Como estamos ligados a um Switch (Camada 2), o sniffer só apanha tráfego Unicast se for gerado **de** ou **para** ele mesmo. Vamos usar o SrvWeb como alvo.

#### ARP + ICMP (Ping)

Abre um **segundo terminal** no nó PcSniffer e corre:

```bash
ip neigh flush all
ping -c 3 10.0.2.10
```

#### TCP

```bash
# Terminal no nó SrvWeb (Servidor):
nc -lp 1234
```

```bash
# 2º terminal do PcSniffer (Cliente):
nc 10.0.2.10 1234
# Escreve uma mensagem, prime Enter e depois Ctrl+C para fechar a ligação.
```

#### UDP

```bash
# Terminal no nó SrvWeb (Servidor):
nc -u -lp 5000
```

```bash
# Terminal do PcSniffer (Cliente):
echo "teste UDP" | nc -u 10.0.2.10 5000
```

#### HTTP

```bash
# Terminal no nó SrvWeb (Servidor):
python3 -m http.server 80
```

```bash
# Terminal do PcSniffer (Cliente):
curl http://10.0.2.10
# (Ou podes usar: wget http://10.0.2.10 -q -O /dev/null)
```



### 3. Parar a Captura

No **1º terminal** do PcSniffer, pressiona **Ctrl+C**. O programa irá calcular as estatísticas finais e o ficheiro de log será guardado na pasta `logs`.


## Como correr no PC real (Parte B)
 
```bash
# Captura geral na interface Wi-Fi
sudo python3 main.py -i wlo1 --log ../logs/parteb.json
 
# Só DNS (porta 53)
sudo python3 main.py -i wlo1 --port 53 --log ../logs/dns.json
 
# Só HTTP (porta 80)
sudo python3 main.py -i wlo1 --port 80
 
# Captura DHCP
sudo python3 main.py -i wlo1 -p DHCP
 
# Com stats periódicas
sudo python3 main.py -i wlo1 --stats-interval 10 --log ../logs/real.json
```
 
Para gerar tráfego DNS num segundo terminal:
 
```bash
nslookup google.com
nslookup youtube.com
```
 

