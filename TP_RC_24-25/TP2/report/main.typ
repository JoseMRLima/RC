#import "lib.typ": conf

#show: conf.with(
  titulo: "Trabalho Prático 2",
  uc: "Redes de Computadores",
  sigla: "RC",
  grupo: "30",
  ano: "2025/2026",
  alunos: (
    (id: "A106842", nome: "Gonçalo Rodrigues Ribeiro"),
    (id: "A106888", nome: "José Mário Raimundo Lima"),
    (id: "A108961", nome: "Rodrigo Novais da Silva"),
  ),
)

// ══════════════════════════════════════════════════════════════
= Introdução
// DICA: 1 parágrafo curto. Diz o que é o trabalho, o objetivo
// geral (desenvolver um packet sniffer), as duas fases (CORE e
// PC real), e a linguagem escolhida (Python com Scapy).
// Exemplo: "Este trabalho consiste no desenvolvimento de um
// packet sniffer em Python, utilizando a biblioteca Scapy,
// capaz de capturar, identificar e registar tráfego de rede
// em ambiente emulado (CORE) e em interface real (Wi-Fi)."

Este trabalho consiste no desenvolvimento de um packet sniffer capaz de capturar, identificar e registar tráfego de rede. O objetivo é observar e analisar pacotes em tempo real, identificando os protocolos presentes em cada camada — desde o nível de ligação (ARP, Ethernet) até ao nível de aplicação (HTTP, DNS). O trabalho divide-se em duas partes: a Parte A, onde o sniffer é testado num ambiente emulado com o CORE, e a Parte B, onde é usado numa interface real do PC (Wi-Fi). A linguagem escolhida foi Python com Scapy, pela facilidade de inspecionar e desmontar pacotes camada a camada.

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Arquitetura do Sniffer
// DICA: Explica a divisão em módulos e porque fizeste assim.
// Inclui um diagrama (pode ser feito em Typst ou como imagem)
// mostrando o fluxo: pacote → capture.py → analyzer.py →
// filtros → logger.py. Descreve cada módulo em 2-3 frases.

O sniffer está dividido em módulos com responsabilidades bem separadas, o que facilita a manutenção e a adição de novas funcionalidades. O fluxo de um pacote é o seguinte:

```
Interface de rede
      ↓
  capture.py  ← recebe cada pacote via sniff()
      ↓
  analyzer.py ← identifica o protocolo e extrai os campos
      ↓
  filtros     ← protocolo, IP, MAC, porta
      ↓
  rtt.py / flows.py  ← medição de RTT e estado TCP
      ↓
  logger.py   ← output na consola e/ou ficheiro
```

== main.py
// DICA: Ponto de entrada. Trata dos argumentos da linha de
// comando com argparse. Lista as flags disponíveis: -i, -p,
// --ip, --mac, --bpf, --port, -n, --log, --no-live, -v,
// --timeout, --stats-interval. Cria o Logger e chama
// start_capture().

É o ponto de entrada do programa. Usa a biblioteca `argparse` para tratar todos os argumentos da linha de comando: interface (`-i`), filtros (`-p`, `--ip`, `--mac`, `--bpf`, `--port`), número de pacotes (`-n`), ficheiro de log (`--log`), modo verbose (`-v`), timeout (`--timeout`) e estatísticas periódicas (`--stats-interval`). Depois de configurar o `Logger`, chama `start_capture()` com todos os parâmetros.

== capture.py
// DICA: Motor de captura. Usa sniff() do Scapy com um callback
// (packet_callback) chamado para cada pacote. Aplica os filtros
// por protocolo, IP, MAC e porta. Integra o RTTTracker e o
// FlowTracker. Lança threads de background para alertas de
// timeout ICMP e stats periódicas.

É o motor de captura. Chama `sniff()` do Scapy com um callback (`packet_callback`) que é executado para cada pacote recebido. Dentro do callback, o pacote é analisado pelo `analyzer.py` e depois passado pelos filtros de protocolo, IP, MAC e porta. Integra também o `RTTTracker` e o `FlowTracker` para as funcionalidades extra. Duas threads correm em segundo plano: uma verifica sempre se há pings ICMP sem resposta (timeout > 2s) e outra, opcional, imprime estatísticas a cada N segundos.


== analyzer.py
// DICA: Cérebro do sniffer. Recebe um pacote Scapy bruto e
// devolve um dicionário com todos os campos. Usa haslayer()
// para identificar o protocolo camada a camada. Mostra um
// excerto de código para um protocolo (ex: ICMP) para ilustrar
// a lógica.

É o módulo de identificação de protocolos. Recebe um pacote Scapy bruto e devolve um dicionário com todos os campos relevantes (timestamp, IPs, portas, protocolo, resumo). A identificação é feita camada a camada usando `haslayer()` — primeiro verifica ARP, depois ICMP, depois DNS, UDP, TCP e HTTP. O exemplo seguinte mostra como é identificado o ICMP:

```python
if pkt.haslayer(ICMP):
    icmp = pkt[ICMP]
    info["protocol"] = "ICMP"
    type_map = {0: "echo reply", 8: "echo request", ...}
    t = type_map.get(icmp.type, f"type={icmp.type}")
    ...
    info["summary"] = f"ICMP {t} id={icmp.id} seq={icmp.seq}"
```

== logger.py
// DICA: Responsável pelo output. Dois modos de consola: simples
// (tempo relativo, default) e verbose (-v, timestamp completo
// com MACs e tamanho). Suporta log simultâneo em .json, .csv
// e .txt. Mostra estatísticas no final (total de pacotes,
// bytes, taxa, breakdown por protocolo).

Gere todo o output do sniffer. Na consola, tem dois modos: o modo simples (padrão) mostra o tempo relativo desde o início da captura, o protocolo, os IPs e um resumo; o modo verbose (`-v`) mostra o timestamp completo, a interface, os endereços MAC e o tamanho em bytes. Em paralelo, pode guardar os dados em ficheiro nos formatos `.json`, `.csv` ou `.txt` — o ficheiro guarda sempre o formato completo, independentemente do modo da consola. Quando a captura termina (Ctrl+C), imprime um resumo final com o total de pacotes, bytes, duração, taxa e uma barra de distribuição por protocolo.


== rtt.py e flows.py
// DICA: Módulos extra. rtt.py mede o RTT entre ICMP echo
// request e echo reply usando time.perf_counter(). Também
// deteta timeouts (requests sem reply após 2s). flows.py
// rastreia o estado das ligações TCP (SYN_SENT → SYN_RCVD →
// ESTABLISHED → FIN_WAIT → CLOSED).

O `rtt.py` mede o tempo de ida e volta (RTT) de pings ICMP. Quando chega um _echo request_, guarda o instante com `time.perf_counter()`. Quando chega o _echo reply_ correspondente (mesmo `id` e `seq`), calcula a diferença e adiciona o resultado ao resumo do pacote. Deteta ainda timeouts: se um request não tiver resposta em 2 segundos, imprime um alerta na consola.

O `flows.py` rastreia o estado de cada ligação TCP como uma máquina de estados: `SYN_SENT → SYN_RCVD → ESTABLISHED → FIN_WAIT → CLOSED`. Cada transição é assinalada na consola a verde. No final, apresenta uma tabela com todos os fluxos observados, com origem, destino, estado, número de pacotes e bytes transferidos.


#pagebreak()


// ══════════════════════════════════════════════════════════════
= Protocolos Identificados

Para cada protocolo, a análise está organizada em quatro partes: definição, lógica de identificação no `analyzer.py`, diagrama de troca de mensagens e excerto de captura real.

// ──────────────────────────────────────────────────────────────
== ARP (Address Resolution Protocol)

*Definição:* O ARP mapeia endereços IP em endereços MAC. Antes de enviar um pacote, um nó precisa de descobrir o MAC do destinatário — envia um _request_ em broadcast e aguarda a _reply_ direta.

*Camada:* Ligação de Dados (Camada 2) — opera diretamente sobre Ethernet, sem cabeçalho IP. Por isso não atravessa routers e só é visível na rede local.

*Identificação no `analyzer.py`:*

```python
if pkt.haslayer(ARP):
    arp = pkt[ARP]
    info["protocol"] = "ARP"
    info["src_ip"]   = arp.psrc
    info["dst_ip"]   = arp.pdst
    op = "request" if arp.op == 1 else "reply"
    info["summary"] = (
        f"ARP {op}: who has {arp.pdst}? Tell {arp.psrc}"
        if arp.op == 1
        else f"ARP reply: {arp.psrc} is at {arp.hwsrc}"
    )
```

O campo `op` é a "impressão digital" do ARP: valor `1` identifica um _request_, valor `2` uma _reply_. O campo `hwsrc` contém o MAC que o remetente anuncia.

*Diagrama de funcionamento:*

```
PcSniffer (10.0.0.20) → broadcast:       ARP request: who has 10.0.2.10?
SrvWeb    (10.0.2.10) → PcSniffer:       ARP reply:   10.0.2.10 is at 00:00:00:bb:00:01
```

*Captura observada (excerto de `captura.json`):*

```json
{"protocol": "ARP",
 "src_mac":  "00:00:00:aa:00:00",
 "dst_mac":  "ff:ff:ff:ff:ff:ff",
 "src_ip":   "10.0.0.20",
 "dst_ip":   "10.0.2.10",
 "summary":  "ARP request: who has 10.0.2.10? Tell 10.0.0.20"}

{"protocol": "ARP",
 "src_mac":  "00:00:00:bb:00:01",
 "dst_mac":  "00:00:00:aa:00:00",
 "src_ip":   "10.0.2.10",
 "dst_ip":   "10.0.0.20",
 "summary":  "ARP reply: 10.0.2.10 is at 00:00:00:bb:00:01"}
```

O `dst_mac = ff:ff:ff:ff:ff:ff` confirma que o _request_ é enviado em broadcast — o switch encaminha-o para todas as portas, permitindo que o PcSniffer o capture mesmo sem ser o destinatário final.

// ──────────────────────────────────────────────────────────────
== ICMP (Internet Control Message Protocol)

*Definição:* O ICMP é usado para diagnóstico de rede. O comando `ping` envia um _echo request_ (tipo 8) e aguarda um _echo reply_ (tipo 0). O par partilha os campos `id` e `seq`, o que permite emparelhar pedido e resposta para calcular o RTT.

*Camada:* Rede (Camada 3) — encapsulado diretamente em IPv4, sem cabeçalho de transporte (TCP/UDP). O tipo de mensagem está no primeiro byte do cabeçalho ICMP.

*Identificação no `analyzer.py`:*

```python
if pkt.haslayer(ICMP):
    icmp = pkt[ICMP]
    info["protocol"] = "ICMP"
    type_map = {
        0: "echo reply",
        8: "echo request",
        3: "dest unreachable",
        11: "time exceeded"
    }
    t = type_map.get(icmp.type, f"type={icmp.type}")
    info["icmp_type"] = icmp.type
    info["icmp_id"]   = icmp.id
    info["icmp_seq"]  = icmp.seq
    info["summary"]   = f"ICMP {t} id={icmp.id} seq={icmp.seq}"
```

O `rtt.py` regista o instante do _request_ com `time.perf_counter()` e, quando chega o _reply_ com o mesmo `(id, seq)`, calcula a diferença em milissegundos.

*Diagrama de funcionamento:*

```
PcSniffer → SrvWeb:    ICMP echo request  type=8  id=36  seq=1
SrvWeb    → PcSniffer: ICMP echo reply    type=0  id=36  seq=1   [RTT=2.1ms]
```

*Captura observada (excerto de `captura.json`):*

```json
{"protocol": "ICMP",
 "src_ip":   "10.0.0.20",
 "dst_ip":   "10.0.2.10",
 "summary":  "ICMP echo request id=36 seq=1"}

{"protocol": "ICMP",
 "src_ip":   "10.0.2.10",
 "dst_ip":   "10.0.0.20",
 "summary":  "ICMP echo reply id=36 seq=1  [RTT=2.134ms]"}
```

O `type=8` identifica o _request_ e o `type=0` o _reply_. O `id` e `seq` iguais provam que pertencem ao mesmo ciclo de ping.

// ──────────────────────────────────────────────────────────────
== ICMPv6

*Definição:* O ICMPv6 é o equivalente IPv6 do ICMP, mas com funções alargadas. Além do diagnóstico (echo request/reply), é responsável pelo Neighbor Discovery Protocol (NDP), que substitui o ARP em IPv6 — os nós usam Neighbor Solicitation (NS) e Neighbor Advertisement (NA) para descobrir os MACs dos vizinhos.

*Camada:* Rede (Camada 3) — encapsulado diretamente em IPv6. O NDP substitui funcionalmente o ARP da Camada 2, mas opera ao nível IP.

*Identificação no `analyzer.py`:*

```python
# Echo request/reply — mesmo mecanismo que ICMP mas tipos diferentes
if pkt.haslayer(ICMPv6EchoRequest):
    v6 = pkt[ICMPv6EchoRequest]
    info["protocol"] = "ICMPv6"
    info["icmp_type"] = 128   # echo request
    info["icmp_id"]   = v6.id
    info["icmp_seq"]  = v6.seq
    info["summary"]   = f"ICMPv6 echo request id={v6.id} seq={v6.seq}"

if pkt.haslayer(ICMPv6EchoReply):
    v6 = pkt[ICMPv6EchoReply]
    info["protocol"] = "ICMPv6"
    info["icmp_type"] = 129   # echo reply
    info["summary"]   = f"ICMPv6 echo reply id={v6.id} seq={v6.seq}"

# Neighbor Discovery
if pkt.haslayer(ICMPv6ND_NS):
    info["protocol"] = "ICMPv6"
    info["summary"]  = f"ICMPv6 Neighbor Solicitation → {pkt[ICMPv6ND_NS].tgt}"

if pkt.haslayer(ICMPv6ND_NA):
    info["protocol"] = "ICMPv6"
    info["summary"]  = f"ICMPv6 Neighbor Advertisement: {pkt[ICMPv6ND_NA].tgt}"
```

A distinção entre echo request (tipo 128) e echo reply (tipo 129) é análoga ao ICMP IPv4 (tipos 8 e 0). O Neighbor Solicitation é enviado em multicast para descobrir o MAC de um endereço IPv6, e o Neighbor Advertisement responde diretamente ao solicitante.

*Diagrama de funcionamento (Neighbor Discovery):*

```
PcSniffer → multicast:   ICMPv6 Neighbor Solicitation → 2001:2::10
SrvWeb    → PcSniffer:   ICMPv6 Neighbor Advertisement: 2001:2::10
```

*Captura observada na interface real — Parte B:*

```json
{"protocol": "ICMPv6",
 "src_ip":   "fe80::15a3:72cf:1441:aacf",
 "dst_ip":   "ff02::1:ff41:aacf",
 "summary":  "ICMPv6 Neighbor Solicitation → fe80::200:ff:feaa:1"}

{"protocol": "ICMPv6",
 "src_ip":   "fe80::200:ff:feaa:1",
 "dst_ip":   "fe80::15a3:72cf:1441:aacf",
 "summary":  "ICMPv6 Neighbor Advertisement: fe80::200:ff:feaa:1"}
```

O ICMPv6 foi observado principalmente na Parte B, onde o sistema operativo gera automaticamente mensagens de Neighbor Discovery para manter a tabela de vizinhos IPv6. O Neighbor Solicitation é enviado para o endereço multicast do nó solicitado (`ff02::1:ff__:____`, derivado dos últimos 24 bits do alvo), e o Neighbor Advertisement responde diretamente ao solicitante via unicast.



// ──────────────────────────────────────────────────────────────
== TCP (Transmission Control Protocol)

*Definição:* O TCP garante entrega ordenada dos dados através de um _three-way handshake_ (SYN → SYN-ACK → ACK) para estabelecer a ligação e de um fecho negociado com FIN.

*Camada:* Transporte (Camada 4) — encapsulado em IP. Identificado pelo campo `protocol=6` no cabeçalho IP. As flags de controlo (SYN, ACK, FIN, RST, PSH) estão num campo de 8 bits do cabeçalho TCP.

*Identificação no `analyzer.py` e `flows.py`:*

```python
# analyzer.py — extração de flags e portas
if pkt.haslayer(TCP):
    tcp = pkt[TCP]
    info["src_port"]      = tcp.sport
    info["dst_port"]      = tcp.dport
    info["tcp_flags_int"] = int(tcp.flags)
    flags = _tcp_flags(tcp.flags)   # ex: "SYN", "SYN|ACK", "FIN|ACK"
    info["summary"] = f"TCP [{flags}] {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport}"

def _tcp_flags(flags) -> str:
    names = {0x01:"FIN", 0x02:"SYN", 0x04:"RST",
             0x08:"PSH", 0x10:"ACK", 0x20:"URG"}
    active = [n for bit, n in names.items() if int(flags) & bit]
    return "|".join(active) if active else str(flags)
```

#pagebreak()
*Diagrama de funcionamento:*

```
PcSniffer → SrvWeb:    [SYN]               ← início do handshake
SrvWeb    → PcSniffer: [SYN|ACK]
PcSniffer → SrvWeb:    [ACK]               ← ligação ESTABLISHED
PcSniffer → SrvWeb:    [PSH|ACK]           ← dados enviados
SrvWeb    → PcSniffer: [ACK]
PcSniffer → SrvWeb:    [FIN|ACK]           ← início do fecho
SrvWeb    → PcSniffer: [FIN|ACK]
PcSniffer → SrvWeb:    [ACK]               ← ligação CLOSED
```

*Captura observada (excerto de `logs/tcp.json`):*

```json
{"protocol":"TCP","src_ip":"10.0.0.20","dst_ip":"10.0.2.10",
 "src_port":54321,"dst_port":1234,
 "summary":"TCP [SYN] 10.0.0.20:54321 → 10.0.2.10:1234"}

{"protocol":"TCP","src_ip":"10.0.2.10","dst_ip":"10.0.0.20",
 "src_port":1234,"dst_port":54321,
 "summary":"TCP [SYN|ACK] 10.0.2.10:1234 → 10.0.0.20:54321"}

{"protocol":"TCP","src_ip":"10.0.0.20","dst_ip":"10.0.2.10",
 "src_port":54321,"dst_port":1234,
 "summary":"TCP [ACK] 10.0.0.20:54321 → 10.0.2.10:1234"}
```

A sequência SYN → SYN|ACK → ACK confirma o _three-way handshake_. O `flows.py` assinalou automaticamente cada transição na consola a verde.

// ──────────────────────────────────────────────────────────────
== UDP (User Datagram Protocol)

*Definição:* O UDP é um protocolo sem ligação — envia datagramas sem handshake nem confirmação de entrega (_fire and forget_). É mais rápido que o TCP mas sem garantias de ordem ou chegada.

*Camada:* Transporte (Camada 4) — encapsulado em IP, identificado pelo campo `protocol=17` no cabeçalho IP. O cabeçalho UDP tem apenas 8 bytes (portas, comprimento e checksum), o que o torna significativamente mais leve que o TCP.

*Identificação no `analyzer.py`:*

```python
# O UDP só é identificado após descartar DHCP e DNS,
# que também usam UDP mas têm camadas próprias.
if pkt.haslayer(UDP):
    udp = pkt[UDP]
    info["src_port"] = udp.sport
    info["dst_port"] = udp.dport
    info["protocol"] = "UDP"
    info["summary"]  = (
        f"UDP {src_ip}:{udp.sport} → {dst_ip}:{udp.dport}"
    )
```

*Diagrama de funcionamento:*

```
PcSniffer → SrvWeb:   UDP datagram  porta 5000
                      (sem confirmação — não há ACK de volta)
```

*Captura observada (excerto de `logs/udp.json`):*

```json
{"protocol": "UDP",
 "src_ip":   "10.0.0.20",
 "dst_ip":   "10.0.2.10",
 "src_port": 43108,
 "dst_port": 5000,
 "summary":  "UDP 10.0.0.20:43108 → 10.0.2.10:5000"}
```

Ao contrário do TCP, existe apenas uma linha por envio — não há ACK. Isto ilustra a diferença fundamental entre os dois protocolos de transporte.

// ──────────────────────────────────────────────────────────────
== HTTP (HyperText Transfer Protocol)

*Definição:* O HTTP é um protocolo de camada de aplicação que funciona sobre TCP (porta 80). Segue um modelo pedido-resposta: o cliente envia um método (`GET`, `POST`, etc.) e o servidor responde com um código de estado e conteúdo.

*Camada:* Aplicação (Camada 7) — sobre TCP/IP. Ao contrário dos protocolos de rede e transporte, não tem um campo de identificação fixo no cabeçalho IP/TCP; a deteção é feita por heurística sobre o payload.

*Identificação no `analyzer.py`:*

```python
# Deteção heurística: porta 80/8080 + inspeção do payload
if (tcp.dport in (80, 8080) or tcp.sport in (80, 8080)) \
        and pkt.haslayer(Raw):
    payload = pkt[Raw].load.decode(errors="replace")
    http_info = _parse_http(payload)
    if http_info:
        info["protocol"] = "HTTP"
        info["summary"]  = http_info

def _parse_http(payload: str):
    first_line = payload.split("\r\n")[0]
    parts = first_line.split(" ", 2)
    HTTP_METHODS = ("GET","POST","PUT","DELETE","HEAD","OPTIONS")
    if parts[0] in HTTP_METHODS:
        return f"HTTP {parts[0]} {parts[1]} {parts[2]}"
    if parts[0].startswith("HTTP/"):
        return f"HTTP {parts[0]} {parts[1]} {parts[2]}"
    return None
```

A deteção é feita em duas etapas: primeiro verifica a porta, depois inspeciona a primeira linha do payload para identificar um método HTTP ou uma resposta `HTTP/x.x`.

*Diagrama de funcionamento:*

```
[TCP handshake — 3 pacotes]
PcSniffer → SrvWeb:    HTTP GET / HTTP/1.1
SrvWeb    → PcSniffer: HTTP/1.0 200 OK  (+ conteúdo HTML)
[TCP fecho — 3 pacotes]
```

*Captura observada (excerto de `logs/http.json`):*

```json
{"protocol": "HTTP",
 "src_ip":   "10.0.0.20",
 "dst_ip":   "10.0.2.10",
 "src_port": 54832,
 "dst_port": 80,
 "summary":  "HTTP GET / HTTP/1.1"}

{"protocol": "HTTP",
 "src_ip":   "10.0.2.10",
 "dst_ip":   "10.0.0.20",
 "src_port": 80,
 "dst_port": 54832,
 "summary":  "HTTP HTTP/1.0 200 OK"}
```

O par GET + 200 OK confirma o ciclo pedido-resposta. O sniffer filtra apenas os pacotes com payload HTTP, ignorando os pacotes TCP do handshake e do fecho.

// ──────────────────────────────────────────────────────────────
== DHCP (Dynamic Host Configuration Protocol)

*Definição:* O DHCP atribui automaticamente configurações de rede (IP, máscara, gateway, DNS) a clientes que se ligam à rede. Usa UDP nas portas 67 (servidor) e 68 (cliente) e segue um ciclo de quatro mensagens: Discover → Offer → Request → ACK.

*Camada:* Aplicação (Camada 7) — sobre UDP/IP. O Scapy deteta-o pela presença da camada BOOTP (base do DHCP) e pelas opções DHCP no payload UDP. A identificação do subtipo de mensagem requer leitura das opções, pois não há campo fixo no cabeçalho.

*Identificação no `analyzer.py`:*

```python
if pkt.haslayer(DHCP):
    dhcp = pkt[DHCP]
    msg_types = {
        1: "Discover", 2: "Offer", 3: "Request",
        4: "Decline", 5: "ACK", 6: "NAK",
        7: "Release", 8: "Inform",
    }
    # O tipo de mensagem está nas opções DHCP
    msg_type_opt = next(
        (opt[1] for opt in dhcp.options
         if isinstance(opt, tuple) and opt[0] == "message-type"),
        None,
    )
    label = msg_types.get(msg_type_opt, f"type={msg_type_opt}")
    info["protocol"] = "DHCP"
    info["summary"]  = f"DHCP {label}"
    if pkt.haslayer(BOOTP):
        info["src_ip"] = pkt[BOOTP].ciaddr or "0.0.0.0"
```

O tipo de mensagem DHCP não está num campo fixo do cabeçalho — está codificado nas opções DHCP (opção 53). O código percorre a lista de opções até encontrar `"message-type"` e converte o valor numérico para o nome legível.

*Diagrama de funcionamento (DORA):*

```
Cliente → broadcast:   DHCP Discover   (porta 68 → 67)
Servidor → Cliente:    DHCP Offer      (IP proposto)
Cliente → broadcast:   DHCP Request    (aceitar o IP)
Servidor → Cliente:    DHCP ACK        (confirmação)
```

*Nota sobre captura:* O DHCP não foi possível capturar no CORE porque a topologia usa endereçamento estático — os IPs são configurados diretamente nos nós sem servidor DHCP. Na interface real (Parte B), o IP já estava atribuído quando o sniffer foi iniciado. Para forçar uma captura DHCP seria necessário executar `sudo dhclient -r wlo1 && sudo dhclient wlo1`, o que implicaria interromper momentaneamente a ligação à rede. O suporte a DHCP está implementado e funcional no código — basta gerar o tráfego correspondente.

// ──────────────────────────────────────────────────────────────
== DNS (Domain Name System)

*Definição:* O DNS traduz nomes de domínio em endereços IP. Usa UDP na porta 53 (também TCP para respostas grandes). O cliente envia uma _query_ (`qr=0`) e o servidor responde com uma _response_ (`qr=1`) contendo o endereço resolvido.

*Camada:* Aplicação (Camada 7) — sobre UDP (porta 53). O bit `qr` no cabeçalho DNS distingue query de response; o tipo de registo (`A`, `AAAA`, `CNAME`) indica o que foi pedido.

*Identificação no `analyzer.py`:*

```python
if pkt.haslayer(DNS):
    dns = pkt[DNS]
    info["protocol"] = "DNS"
    if pkt.haslayer(UDP):
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

    if dns.qr == 0 and pkt.haslayer(DNSQR):          # query
        qname = pkt[DNSQR].qname.decode().rstrip(".")
        qtype_map = {1:"A", 28:"AAAA", 5:"CNAME", ...}
        qtype = qtype_map.get(pkt[DNSQR].qtype, "?")
        info["summary"] = f"DNS query {qtype} {qname}"

    elif dns.qr == 1 and pkt.haslayer(DNSRR):        # response
        rname = pkt[DNSRR].rrname.decode().rstrip(".")
        rdata = pkt[DNSRR].rdata
        info["summary"] = f"DNS response: {rname} → {rdata}"
```

O campo `qr` é o bit que distingue query de response. O tipo de registo (`A` para IPv4, `AAAA` para IPv6) é extraído do campo `qtype`.

*Diagrama de funcionamento:*

```
PC → servidor DNS (porta 53):   DNS query A  google.com      (qr=0)
servidor DNS → PC:              DNS response: google.com      (qr=1)
                                             → 142.250.185.46
```

*Captura observada na interface real — Parte B (excerto de `logs/parteb_dns.json`):*

```json
{"protocol": "DNS",
 "src_port": 5353,
 "dst_port": 5353,
 "summary":  "DNS query A google.com"}

{"protocol": "DNS",
 "src_port": 5353,
 "dst_port": 5353,
 "summary":  "DNS response: google.com → 142.250.185.46"}
```

O DNS foi capturado na Parte B porque a topologia CORE usa endereçamento estático sem servidor DNS. O tráfego mDNS (porta 5353) é gerado automaticamente pelo sistema operativo durante a navegação normal.


#pagebreak()


// ══════════════════════════════════════════════════════════════
= Filtros e Parâmetros de Execução
// DICA: Cria uma tabela com todas as flags, o que fazem e um
// exemplo de uso. O enunciado pede explicitamente "lista de
// filtros e parâmetros de entrada disponíveis".

// Tabela sugerida com colunas: Flag | Descrição | Exemplo
//
// | -i / --interface | Interface a escutar (obrigatório) | -i eth0 |
// | -p / --protocol  | Filtrar por protocolo             | -p ICMP |
// | --ip             | Filtrar por endereço IP           | --ip 10.0.5.10 |
// | --mac            | Filtrar por endereço MAC          | --mac 00:00:00:aa:00:01 |
// | --bpf            | Filtro BPF personalizado          | --bpf "tcp port 80" |
// | --port           | Filtrar por porta                 | --port 53 |
// | -n / --count     | Nº de pacotes (0=infinito)        | -n 10 |
// | --log            | Ficheiro de log                   | --log cap.json |
// | --no-live        | Só log, sem consola               | --no-live |
// | -v / --verbose   | Modo verbose (timestamp completo) | -v |
// | --timeout        | Tempo máximo em segundos          | --timeout 30 |
// | --stats-interval | Stats periódicas a cada N seg     | --stats-interval 10 |
//
// DICA EXTRA: O Scapy passa o filtro BPF diretamente ao
// libpcap — qualquer expressão BPF válida é suportada.
// Isso permite filtros complexos como "host X and port 80".

O sniffer aceita os seguintes parâmetros na linha de comando:

#table(
  columns: (auto, 1fr, auto),
  align: (left, left, left),
  table.header([*Flag*], [*Descrição*], [*Exemplo*]),
  [`-i` / `--interface`], [Interface de rede a escutar (obrigatório)], [`-i eth0`],
  [`-p` / `--protocol`],  [Filtrar apenas por um protocolo], [`-p ICMP`],
  [`--ip`],               [Filtrar por endereço IP (origem ou destino)], [`--ip 10.0.5.10`],
  [`--mac`],              [Filtrar por endereço MAC (origem ou destino)], [`--mac 00:00:00:aa:00:01`],
  [`--bpf`],              [Filtro BPF livre, passado ao libpcap], [`--bpf "tcp port 80"`],
  [`--port`],             [Filtrar por número de porta], [`--port 53`],
  [`-n` / `--count`],     [Número de pacotes a capturar (0 = sem limite)], [`-n 20`],
  [`--log`],              [Guardar captura em ficheiro (.json, .csv ou .txt)], [`--log cap.json`],
  [`--no-live`],          [Desligar output na consola (apenas ficheiro)], [`--no-live`],
  [`-v` / `--verbose`],   [Modo verbose: timestamp completo, MACs e tamanho], [`-v`],
  [`--timeout`],          [Parar a captura após N segundos], [`--timeout 30`],
  [`--stats-interval`],   [Mostrar estatísticas a cada N segundos], [`--stats-interval 10`],
)

Os filtros `-p`, `--ip`, `--mac` e `--port` são aplicados em Python depois da captura. O filtro `--bpf` é passado diretamente ao libpcap (motor interno do Scapy), o que permite expressões mais complexas como `"host 10.0.5.10 and tcp port 80"`. Os dois tipos de filtro podem ser combinados.

Exemplo de uso completo:
```
sudo python3 main.py -i eth0 -p TCP --ip 10.0.5.10 --log tcp.json -v --timeout 60
```

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Logging e Persistência de Dados
// DICA: Explica os 3 formatos suportados e mostra um exemplo
// de cada. O enunciado pede "exposição dos mecanismos de
// logging implementados".

O módulo `logger.py` trata de todo o output do sniffer: o que aparece na consola em tempo real e o que é guardado em ficheiro. Os dois são independentes — é possível ter output na consola sem guardar ficheiro, guardar ficheiro sem output na consola (`--no-live`), ou ambos ao mesmo tempo.

== Modos de Output na Consola

// DICA: Explica os dois modos do live output.
//
// Modo simples (default) — tempo relativo desde o início:
//    0.000s  ICMP  10.0.5.10 → 10.0.0.20  ICMP echo request id=1
//    0.002s  ICMP  10.0.0.20 → 10.0.5.10  ICMP echo reply id=1 [RTT=2.1ms]
//
// Modo verbose (-v) — timestamp completo com todos os campos:
//    [1] 2026-05-04 23:34:08  eth0  ICMP  10.0.5.10 → 10.0.0.20  98B  echo request
//
// Explica que o ficheiro guarda SEMPRE o formato completo,
// independentemente do modo de consola.

Há dois modos de output na consola:

*Modo simples* (padrão) — mostra o tempo decorrido desde o início, o protocolo, os IPs e um resumo curto:
```
   0.000s  ICMP      10.0.5.10                    → 10.0.0.20   ICMP echo request id=36 seq=1
   0.011s  ICMP      10.0.0.20                    → 10.0.5.10   ICMP echo reply id=36 seq=1  [RTT=11.203ms]
   0.125s  ARP       10.0.0.1                     → 10.0.0.20   ARP request: who has 10.0.0.20?
```

*Modo verbose* (`-v`) — mostra o número de sequência, timestamp completo, interface, protocolo, MACs, IPs, tamanho em bytes e resumo:
```
[    1] 2026-04-17 11:39:16.932  eth0      ICMP        10.0.5.10                →  10.0.0.20    98B  ICMP echo request id=36
[    2] 2026-04-17 11:39:16.943  eth0      ICMP        10.0.0.20                →  10.0.5.10    98B  ICMP echo reply id=36  [RTT=11.203ms]
```

O ficheiro de log guarda sempre o formato completo, independentemente do modo escolhido na consola.

== Formato JSON
// DICA: Mostra 2 linhas de exemplo do teu logs/tcp.json.
// Explica os campos: timestamp, interface, protocol, src_mac,
// dst_mac, src_ip, dst_ip, src_port, dst_port, size, summary.
// Vantagem: fácil de processar programaticamente.

O formato JSON guarda cada pacote como um objeto com todos os campos. É o formato mais adequado para processar os dados com scripts ou ferramentas externas.

```json
[
  {"timestamp": "2026-04-17 11:39:16.932", "interface": "eth0",
   "protocol": "ICMP",
   "src_mac": "00:00:00:aa:00:01", "dst_mac": "00:00:00:aa:00:00",
   "src_ip": "10.0.5.10", "dst_ip": "10.0.0.20",
   "src_port": "", "dst_port": "", "size": 98,
   "summary": "ICMP echo request id=36 seq=1"},
  {"timestamp": "2026-04-17 11:39:16.943", "interface": "eth0",
   "protocol": "ICMP",
   "src_mac": "00:00:00:aa:00:00", "dst_mac": "00:00:00:aa:00:01",
   "src_ip": "10.0.0.20", "dst_ip": "10.0.5.10",
   "src_port": "", "dst_port": "", "size": 98,
   "summary": "ICMP echo reply id=36 seq=1  [RTT=11.203ms]"}
]
```

== Formato CSV
// DICA: Mostra o cabeçalho e 1-2 linhas de exemplo.
// Vantagem: pode ser aberto diretamente no Excel/Calc.

O formato CSV usa os mesmos campos do JSON mas em colunas separadas por vírgulas. Pode ser aberto diretamente no Excel ou LibreOffice Calc para análise.

```
timestamp,interface,protocol,src_mac,dst_mac,src_ip,dst_ip,src_port,dst_port,size,summary
2026-04-17 11:39:16.932,eth0,ICMP,00:00:00:aa:00:01,00:00:00:aa:00:00,10.0.5.10,10.0.0.20,,,98,ICMP echo request id=36 seq=1
2026-04-17 11:39:16.943,eth0,ICMP,00:00:00:aa:00:00,00:00:00:aa:00:01,10.0.0.20,10.0.5.10,,,98,ICMP echo reply id=36 seq=1  [RTT=11.203ms]
```

== Formato TXT
// DICA: Mostra 1-2 linhas de exemplo do formato texto.
// Vantagem: legível diretamente no terminal com cat/less.

O formato TXT é o mais legível diretamente no terminal, com colunas alinhadas em texto simples.

```
# RC TP2 — Packet Sniffer Log
----------------------------------------------------------------------------
2026-04-17 11:39:16.932    eth0     ICMP       10.0.5.10          10.0.0.20             98B  ICMP echo request id=36 seq=1
2026-04-17 11:39:16.943    eth0     ICMP       10.0.0.20          10.0.5.10             98B  ICMP echo reply id=36 seq=1  [RTT=11.203ms]
2026-04-17 11:39:16.914    eth0     ARP        10.0.0.1           10.0.0.20             42B  ARP request: who has 10.0.0.20? Tell 10.0.0.1
```

== Estatísticas Finais
// DICA: Mostra o output de estatísticas que aparece no final
// (ao fazer Ctrl+C). Inclui: total de pacotes, bytes, duração,
// taxa em pkt/s e KB/s, breakdown por protocolo com barra,
// RTT ICMP (min/avg/max), e resumo de fluxos TCP.

Quando a captura termina (Ctrl+C ou timeout), o sniffer imprime automaticamente um resumo:

```
────────────────────────────────────────────────────────────
  Total de pacotes : 79
  Total de bytes   : 6842
  Duração          : 183.2s
  Taxa             : 0.4 pkt/s  |  0.0 KB/s
  Protocolos:
    IPv4         53 pacotes  ( 67.1%)  █████████████
    IPv6         14 pacotes  ( 17.7%)  ███
    ICMP          6 pacotes  (  7.6%)  █
    ARP           4 pacotes  (  5.1%)  █
    DNS           2 pacotes  (  2.5%)

  RTT ICMP  min=9.812ms  avg=11.047ms  max=12.104ms  amostras=3

  Fluxos TCP:
    Origem                 Destino                Estado         Pkts    Bytes
    ──────────────────────────────────────────────────────────────────────────
    10.0.5.10:54321        10.0.0.20:1234         CLOSED            8      512
────────────────────────────────────────────────────────────
[INFO] Log guardado em: captura.json
```

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Topologia CORE

A topologia usada no emulador CORE foi definida em conjunto com o docente das aulas práticas. É composta por sete nós distribuídos em duas redes locais ligadas por dois routers, permitindo testar protocolos tanto em comunicação local (mesma rede) como em comunicação inter-redes.

#figure(
  image("imgs/topologia1.png", width: 100%),
  caption: [Topologia CORE utilizada nos testes.]
)

#table(
  columns: (auto, auto, 1fr, 1fr),
  align: (left, left, left, left),
  table.header([*Nó*], [*Tipo*], [*IPv4*], [*IPv6*]),
  [`PcSniffer`], [PC — sniffer],          [`10.0.0.20/24`], [`2001:0::20/64`],
  [`PcClient`],  [PC — gerador de tráfego], [`10.0.0.21/24`], [`2001:0::21/64`],
  [`SW1`],       [Switch L2],             [—],              [—],
  [`RA1`],       [Router],                [`10.0.0.1/24` · `10.0.1.1/24`], [`2001:0::1/64` · `2001:1::1/64`],
  [`RA2`],       [Router],                [`10.0.1.2/24` · `10.0.2.1/24`], [`2001:1::2/64` · `2001:2::1/64`],
  [`SW2`],       [Switch L2],             [—],              [—],
  [`SrvWeb`],    [Servidor Web],          [`10.0.2.10/24`], [`2001:2::10/64`],
  [`SrvDB`],     [Servidor BD],           [`10.0.2.12/24`], [`2001:2::12/64`],
)

O sniffer correu no nó *PcSniffer* (`10.0.0.20`), a escutar a interface `eth0` ligada ao switch SW1. O caminho completo entre PcSniffer e SrvWeb é:

```
PcSniffer → SW1 → RA1 → RA2 → SW2 → SrvWeb
10.0.0.20        10.0.0.1→10.0.1.1  10.0.1.2→10.0.2.1       10.0.2.10
```

A colocação do sniffer no PcSniffer, com a escuta na interface ligada ao SW1, permite capturar todo o tráfego que entra e sai desta máquina — incluindo os dois sentidos de cada comunicação (request e reply). Por estar na mesma rede local que o PcClient, o sniffer também consegue capturar o tráfego ARP em broadcast, que não atravessa routers.

Para gerar tráfego de cada protocolo de forma controlada, foram usados os seguintes comandos. O sniffer estava sempre ativo no PcSniffer com o comando correspondente a cada teste:

#table(
  columns: (auto, 1fr, 1fr),
  align: (left, left, left),
  table.header([*Protocolo*], [*Comando no PcSniffer ou PcClient*], [*Comando no servidor (se necessário)*]),
  [`ARP`],  [`ip neigh flush all && ping -c 1 10.0.2.10`], [—],
  [`ICMP`], [`ping -c 5 10.0.2.10`],                       [—],
  [`TCP`],  [`nc 10.0.2.10 9000`],                          [`nc -l -p 9000` (SrvWeb)],
  [`UDP`],  [`echo "teste" | nc -u 10.0.2.10 5000`],        [`nc -u -l -p 5000` (SrvWeb)],
  [`HTTP`], [`wget http://10.0.2.10/ -q -O /dev/null`],     [`python3 -m http.server 80` (SrvWeb)],
)

DNS e DHCP não são observáveis neste ambiente porque a topologia usa endereçamento estático, os IPs estão configurados diretamente nos nós sem servidor DNS nem DHCP. Estes protocolos foram capturados na interface real (Parte B).

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Testes e Validação
// DICA: Demonstra que o sniffer funciona corretamente,
// comparando com o Wireshark. O enunciado pede "testes
// efetuados para validação do funcionamento da aplicação,
// devidamente explicados e fundamentados".

Para validar o correto funcionamento do sniffer, foram realizados testes sistemáticos para cada funcionalidade principal: filtros, cálculo de RTT e deteção de fluxos TCP. Os resultados foram comparados com capturas paralelas no Wireshark sobre a mesma interface.

== Validação dos Filtros

Para cada filtro disponível, foi verificado que o sniffer captura exatamente os pacotes esperados, usando o Wireshark como referência independente. Os testes foram realizados na interface real do PC (`eth0`).

=== Filtro por protocolo — ICMP (`-p ICMP`)

Comandos executado:
```
Terminal 1 (Sniffer): sudo python3 sniffer/main.py -i eth0 -p ICMP -v
Terminal 2 (Cliente): ping -c 5 8.8.8.8
```


#figure(
  image("imgs/sniffer_ICMP.png", width: 100%),
  caption: [Output do sniffer com filtro `-p ICMP`: 10 pacotes capturados (5 request + 5 reply para 8.8.8.8).]
)

#figure(
  image("imgs/ICMP.png", width: 100%),
  caption: [Comando `ping -c 5 8.8.8.8` que gerou o tráfego ICMP. O ping reporta RTT min/avg/max = 20.453/21.566/23.971 ms.]
)

#figure(
  image("imgs/ICMP-wireshark.png", width: 120%),
  caption: [Wireshark com filtro `icmp`: 10 pacotes ICMP idênticos aos capturados pelo sniffer (id=0x0003, seq=1 a 5).]
)

O sniffer capturou exatamente 10 pacotes ICMP (5 echo request de `172.28.214.45` para `8.8.8.8` e 5 echo reply no sentido inverso), ignorando todo o restante tráfego presente na interface. O Wireshark com filtro `icmp` confirmou os mesmos 10 pacotes com os mesmos identificadores (`id=0x0003`, `seq=1` a `5`). Os RTTs medidos pelo sniffer (ex: 22.071 ms, 22.734 ms) são consistentes com os reportados pelo `ping` (avg=21.566 ms), com a diferença expectável pelo overhead de processamento do Scapy.

#pagebreak()

=== Filtro por protocolo — ARP (`-p ARP`)

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 sniffer/main.py -i eth0 -p ARP -v
Terminal 2 (Cliente): sudo ip neigh flush all && ping -c 5 8.8.8.8
```

#figure(
  image("imgs/sniffer_ARP.png", width: 100%),
  caption: [Output do sniffer com filtro `-p ARP`: 4 pacotes ARP capturados (2 request + 2 reply entre 172.28.214.45 e 172.28.208.1).]
)

#figure(
  image("imgs/ARP.png", width: 100%),
  caption: [Comando que gerou o tráfego: flush da cache ARP seguido de ping, forçando resolução ARP.]
)

#figure(
  image("imgs/ARP-wireshak.png", width: 100%),
  caption: [Wireshark com filtro `arp`: 4 pacotes ARP nas linhas 15, 16, 27, 28 — idênticos aos do sniffer.]
)

O sniffer capturou 4 pacotes ARP: o nó `172.28.214.45` perguntou "who has `172.28.208.1`?" e recebeu resposta, e depois a situação inverteu-se. O Wireshark com filtro `arp` apresentou os mesmos 4 pacotes com as mesmas origens, destinos e conteúdos. Todo o tráfego ICMP gerado pelo `ping` foi corretamente ignorado pelo filtro.

=== Filtro por protocolo — HTTP (`-p HTTP`)

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 sniffer/main.py -i eth0 -p HTTP -v
Terminal 2 (Cliente): curl [http://example.com](http://example.com)
```

#figure(
  image("imgs/sniffer_HTTP.png", width: 100%),
  caption: [Output do sniffer com filtro `-p HTTP`: 2 pacotes HTTP capturados — GET e 200 OK entre 172.28.214.45:42520 e 104.20.23.154:80.]
) <fig-filtro-http-sniffer>

#figure(
  image("imgs/HTTP.png", width: 100%),
  caption: [Comando `curl http://example.com` que gerou o pedido HTTP em claro.]
)

#figure(
  image("imgs/HTTP-wireshark.png", width: 100%),
  caption: [Wireshark com filtro `http`: 2 pacotes HTTP - GET / HTTP/1.1 e HTTP/1.1 200 OK — idênticos aos do sniffer.]
) <fig-filtro-http-wireshark>

Como observado na @fig-filtro-http-sniffer, o sniffer detetou e isolou corretamente os 2 únicos pacotes com payload HTTP presentes nesta transação: o pedido inicial GET / HTTP/1.1 (com 141 Bytes), originado pela porta dinâmica do cliente (172.28.214.45:42520) em direção à porta 80 do servidor (104.20.23.154:80), e a correspondente resposta HTTP/1.1 200 OK (com 903 Bytes) a fluir no sentido inverso.

A captura no Wireshark com o filtro http (@fig-filtro-http-wireshark) validou integralmente o resultado. Um detalhe curioso revelado por este teste é que o motor de filtragem atuou corretamente de forma restritiva: os pacotes TCP da camada de transporte referentes à abertura da ligação (Three-way Handshake) e ao seu encerramento foram descartados, garantindo que o filtro -p HTTP extrai estritamente mensagens da camada de aplicação.

#pagebreak()
=== Filtro por protocolo — DNS (`-p DNS`)

O protocolo DNS é fundamental para o funcionamento da rede, permitindo a tradução de nomes de domínio em endereços IP. Para validar este filtro, monitorizou-se a resolução do domínio `google.com`.

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 -p DNS -v
Terminal 2 (Cliente): nslookup google.com
```

#figure(
image("imgs/sniffer_DNS.png", width: 120%),
caption: [Output do sniffer com filtro -p DNS: captura da query (Standard query A) e da respetiva resposta com a lista de IPs.]
) <fig-filtro-dns-sniffer>

#figure(
image("imgs/DNS-wireshark.png", width: 120%),
caption: [Wireshark com filtro dns: confirmação da transação na porta 53 UDP.]
) <fig-filtro-dns-wireshark>

O sniffer isolou corretamente a transação DNS. Como visível na @fig-filtro-dns-sniffer, a aplicação identifica o tipo de query (A para endereços IPv4) e extrai o conteúdo da resposta diretamente para a consola. O Wireshark (@fig-filtro-dns-wireshark) confirmou que apenas os pacotes UDP na porta 53 foram processados, validando a eficácia do filtro de aplicação.

#pagebreak()

=== Filtro por protocolo — UDP (`-p UDP`)

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 sniffer/main.py -i eth0 -p UDP -v
Terminal 2 (Emissor): echo "teste UDP" | nc -u 127.0.0.1 5000
Terminal 3 (Recetor): nc -u -l -p 5000
```

#figure(
  image("imgs/sniffer_UDP.png", width: 90%),
  caption: [Output do sniffer com filtro `-p UDP`: 10 pacotes UDP capturados, maioritariamente tráfego multicast (239.255.255.250:1900 — SSDP) e broadcast UDP da rede local.]
)

#figure(
  image("imgs/UDP1.png", width: 100%),
  caption: [Geração de tráfego UDP com netcat: `echo "teste UDP" | nc -u 127.0.0.1 5000`.]
)

#figure(
  image("imgs/UDP2.png", width: 100%),
  caption: [Receção do datagrama UDP no servidor netcat: `nc -u -l -p 5000`.]
)

#figure(
  image("imgs/UDP-wireshark.png", width: 120%),
  caption: [Wireshark com filtro `udp`: confirma tráfego UDP na interface, incluindo os mesmos fluxos multicast observados pelo sniffer.]
)

O sniffer capturou 10 pacotes UDP, todos corretamente identificados como UDP. O tráfego gerado com `nc -u` para `127.0.0.1` não é visível na interface `eth0` (loopback não passa pela placa de rede), pelo que os pacotes capturados correspondem a tráfego UDP de background da rede local (SSDP/multicast). O Wireshark com filtro `udp` confirmou o mesmo tipo de tráfego na interface.

#pagebreak()

=== Filtro por protocolo — TCP (`-p TCP`)

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 sniffer/main.py -i eth0 -p TCP -v
Terminal 2 (Cliente): curl http://example.com
```

#figure(
  image("imgs/sniffer_TCP.png", width: 90%),
  caption: [Output do sniffer com filtro `-p TCP`: handshake completo e fecho de ligação entre 172.28.214.45:41386 e 104.20.23.154:80, com deteção automática de SYN, ESTABLISHED e FIN pelo flow tracker.]
)

#figure(
  image("imgs/TCP.png", width: 120%),
  caption: [Comando `curl http://example.com` que gerou a ligação TCP capturada.]
)

#figure(
  image("imgs/TCP-wireshark.png", width: 120%),
  caption: [Wireshark com filtro `tcp`: mesma sequência SYN → SYN-ACK → ACK → dados → FIN confirmada.]
)

O sniffer capturou o ciclo de vida completo da ligação TCP: SYN, SYN-ACK, ACK (handshake), troca de dados (PSH\|ACK), e fecho (FIN\|ACK). O módulo `flows.py` detetou e assinalou automaticamente as transições `TCP SYN — nova ligação`, `TCP ESTABLISHED` e `TCP FIN — fecho de ligação`. O Wireshark com filtro `tcp` confirmou a mesma sequência de flags e os mesmos endereços e portas.

#pagebreak()

=== Filtro por IP (`--ip`)

Para validar a filtragem por endereço IP, o sniffer foi configurado para monitorizar exclusivamente o tráfego associado ao endereço `8.8.8.8`. O teste visou demonstrar a capacidade da aplicação em isolar tráfego específico num cenário de múltiplos fluxos ativos.

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 --ip 8.8.8.8 -v
Terminal 2 (Cliente): ping -c 2 8.8.8.8 && ping -c 2 1.1.1.1
```
#figure(
image("imgs/pings.png", width: 70%),
caption: [Geração de tráfego para dois destinos distintos (8.8.8.8 e 1.1.1.1).]
) <fig-ip-cmd>

#figure(
image("imgs/sniffer34.png", width: 70%),
caption: [Output do sniffer com filtro --ip 8.8.8.8: apenas os 4 pacotes relativos ao IP alvo foram capturados.]
) <fig-ip-sniffer>

#figure(
image("imgs/wireshark35.png", width: 120%),
caption: [Wireshark com filtro ip.addr == 8.8.8.8: confirmação exata dos pacotes intercetados pelo sniffer.]
) <fig-ip-wireshark>

Como demonstrado na @fig-ip-sniffer, o sniffer capturou apenas os pacotes cujo endereço de origem ou destino correspondia a 8.8.8.8. É de notar que, embora o comando executado (@fig-ip-cmd) tenha gerado tráfego simultâneo para o IP 1.1.1.1, estes pacotes foram corretamente descartados pelo motor de filtragem.

A comparação com a captura do Wireshark (@fig-ip-wireshark) valida a precisão do filtro, mostrando que o sniffer ignora eficazmente todo o tráfego que não cumpra o critério de endereço IP especificado, independentemente da atividade na interface.

#pagebreak()

=== Filtro BPF (`--bpf`)

O filtro BPF permite uma filtragem de pacotes extremamente eficiente ao ser processado diretamente pelo motor `libpcap`. Para validar esta funcionalidade, o sniffer foi configurado com a expressão `"tcp port 80"`, visando capturar apenas tráfego HTTP na porta padrão, ignorando qualquer outro protocolo ou porta.

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 --bpf "tcp port 80" -v
Terminal 2 (Cliente): curl [http://example.com](http://example.com) && ping -c 2 8.8.8.8
```

#figure(
image("imgs/sniffer_BPF.png", width: 100%),
caption: [Output do sniffer com filtro BPF "tcp port 80": apenas o tráfego TCP associado à porta 80 é intercetado.]
) <fig-bpf-sniffer>

#figure(
image("imgs/BPF-wireshark.png", width: 100%),
caption: [Wireshark com filtro tcp.port == 80: validação da precisão do filtro BPF delegado ao sistema operativo.]
) <fig-bpf-wireshark>

Como demonstrado na @fig-bpf-sniffer, o sniffer capturou apenas os pacotes TCP relacionados com o pedido web efetuado. É importante notar que, embora tenha ocorrido tráfego ICMP em simultâneo (gerado pelo comando ping), este não foi sequer processado pela aplicação, uma vez que o filtro BPF descarta os pacotes a um nível inferior da stack de rede.

Este teste confirma que a aplicação suporta expressões complexas de filtragem (como "host X and port Y"), permitindo um controlo granular sobre a captura. O resultado é idêntico ao obtido no Wireshark (@fig-bpf-wireshark), com a vantagem de reduzir significativamente o consumo de recursos da CPU ao evitar o processamento de pacotes irrelevantes em Python.

=== Filtro por MAC (`--mac`)

A filtragem por endereço físico (MAC) permite isolar o tráfego de um dispositivo específico na rede local ao nível da Camada 2 (Data Link). Para este teste, o sniffer foi configurado para monitorizar o tráfego associado ao endereço MAC do _gateway_ da rede (`28:41:c6:a7:97:a6`). 

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 --mac 28:41:c6:a7:97:a6 -p ICMP -v
Terminal 2 (Cliente): ping -c 2 8.8.8.8
```

#figure(
image("imgs/pings.png", width: 100%),
caption: [Geração de tráfego ICMP direcionado ao exterior (8.8.8.8).]
)

#figure(
image("imgs/sniffer43.png", width: 100%),
caption: [Output do sniffer com filtro combinado (MAC + ICMP): isolamento total do tráfego que transita pelo router.]
) <fig-mac-sniffer>

#figure(
image("imgs/wireshark36.png", width: 100%),
caption: [Wireshark com filtro eth.addr == 28:41:c6:a7:97:a6: confirmação dos mesmos pacotes na interface física.]
) <fig-mac-wireshark>

Como demonstrado na @fig-mac-sniffer, o sniffer capturou com sucesso os pacotes cujo frame Ethernet continha o endereço MAC do gateway como origem ou destino. Ao utilizar um filtro combinado neste teste, comprovou-se que a aplicação consegue aplicar múltiplas restrições em simultâneo (Camada 2 e Camada 3/4), garantindo uma captura extremamente focada.

A correspondência com o Wireshark (@fig-mac-wireshark) valida que os identificadores e sequências intercetadas pelo sniffer são idênticos aos que circulam na rede, confirmando a integridade da análise de cabeçalhos Ethernet implementada.

#pagebreak()
=== Filtro por porta (`--port`)

A filtragem por número de porta permite isolar tráfego de um serviço específico independentemente do protocolo de transporte (TCP ou UDP). Para este teste, o sniffer foi configurado para capturar apenas pacotes com porta de origem ou destino igual a 80 (HTTP), enquanto em simultâneo se gerava tráfego ICMP para confirmar que era descartado.

Comandos executados:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 --port 80 -v
Terminal 2 (Cliente): curl http://example.com && ping -c 2 8.8.8.8
```

#figure(
image("imgs/port.png", width: 100%),
caption: [Geração de tráfego: pedido HTTP a `example.com` e ping simultâneo para confirmar filtragem.]
) <fig-port-cmd>

#figure(
image("imgs/sniffer_port.png", width: 100%),
caption: [Output do sniffer com filtro `--port 80`: apenas os pacotes TCP com porta de origem ou destino 80 são capturados — o tráfego ICMP não aparece.]
) <fig-port-sniffer>

#figure(
image("imgs/port_wireshark.png", width: 100%),
caption: [Wireshark com filtro `tcp.port == 80 or udp.port == 80`: confirmação dos mesmos pacotes intercetados pelo sniffer.]
) <fig-port-wireshark>

Como demonstrado na @fig-port-sniffer, o sniffer capturou apenas os pacotes cuja porta de origem ou destino era 80, incluindo todos os pacotes TCP do ciclo HTTP completo (handshake, pedido GET, resposta 200 OK e fecho). O tráfego ICMP gerado em paralelo pelo `ping` foi corretamente descartado, mesmo sem qualquer filtro de protocolo adicional.

A diferença em relação ao filtro `-p HTTP` é importante: enquanto `-p HTTP` só mostra os pacotes com payload HTTP (GET e 200 OK), o `--port 80` captura todos os pacotes TCP na porta 80 — incluindo os SYN, SYN-ACK e FIN do handshake e fecho. O Wireshark (@fig-port-wireshark) com filtro `tcp.port == 80 or udp.port == 80` confirmou a mesma sequência de pacotes.

#pagebreak()

== Validação do RTT ICMP

_(Para uma compreensão detalhada da lógica de cálculo e das estruturas de dados utilizadas na obtenção desta métrica, recomenda-se a leitura da @sec-func-rtt)._

O RTT calculado pelo módulo `rtt.py` foi comparado com o RTT reportado diretamente pelo comando `ping`. O teste consistiu em correr o sniffer e o comando `ping` em simultâneo na interface real da máquina e comparar os valores obtidos.

Comandos:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 -p ICMP
Terminal 2 (Cliente): ping -c 5 8.8.8.8
```

#figure(
  image("imgs/fig-ping-rtt.png", width: 100%),
  caption: [Output do comando ping.]
) <fig-ping-rtt>

#figure(
  image("imgs/fig-sniffer-rtt.png", width: 100%),
  caption: [Output do sniffer com RTT.]
) <fig-sniffer-rtt>


Os valores de RTT medidos pelo sniffer (visíveis em cada linha de echo reply na @fig-sniffer-rtt) acompanham de forma perfeitamente consistente a variação reportada nativamente pelo ping (@fig-ping-rtt). Analisando o primeiro pacote capturado, o comando ping reportou um tempo de 56.6 ms, enquanto o sniffer registou 57.116 ms. No último pacote, o ping reportou 18.7 ms e o sniffer mediu 18.134 ms.

Estas diferenças diminutas (na ordem das décimas de milissegundo) são inteiramente normais e devem-se à diferença nos mecanismos de captação temporal: o comando nativo ping processa os pacotes diretamente ao nível do kernel do sistema operativo, enquanto o sniffer faz a interceção e processamento dos pacotes no user space através da biblioteca Scapy.

#pagebreak()

== Validação do TCP Flow Tracking 
// DICA: Mostra que o sniffer detetou corretamente as fases
// da ligação TCP no log (SYN → ESTABLISHED → FIN).
// Compara com o que o Wireshark mostra na coluna "Info".

_(Para uma análise aprofundada sobre a máquina de estados finitos (FSM) utilizada para rastrear as ligações e os critérios de transição entre estados, consulte a secção @sec-func-tcp)._

Para validar a deteção das fases da ligação TCP, foi estabelecida uma ligação HTTP completa e verificado se o sniffer detetou corretamente o handshake, a transferência de dados e o fecho.

Comandos executados:
```
Terminal (Sniffer): sudo python3 sniffer/main.py -i eth0 -p TCP -v
Terminal (Cliente): curl [http://example.com](http://example.com)
```

#align(center)[
  #figure(
    image("imgs/sniffer_TCP.png", width: 90%),
    caption: [Sniffer TCP]
  ) <fig-flow-sniffer>
]

#align(center)[
  #figure(
    image("imgs/TCP.png", width: 120%),
    caption: [Comando TCP]
  )
]

#align(center)[
  #figure(
    image("imgs/TCP-wireshark.png", width: 120%),
    caption: [TCP Wireshark]
  ) <fig-flow-wireshark>
]

Como demonstrado na @fig-flow-sniffer, o sniffer detetou com precisão as três fases principais do fluxo entre o cliente (172.28.214.45) e o servidor (104.20.23.154):

1.Handshake: Identificado pela flag [SYN] seguida da mensagem TCP SYN — nova ligação.

2.Estabelecimento: Identificado após o terceiro passo do handshake, resultando no estado TCP ESTABLISHED.

3.Encerramento: Identificado pela flag [FIN|ACK] e assinalado com TCP FIN — fecho de ligação.

A correspondência com a @fig-flow-wireshark é total, validando que o flow tracker consegue manter o estado da ligação mesmo num ambiente com múltiplos pacotes, associando corretamente as respostas aos pedidos através do par de portas e endereços IP.

#pagebreak()

== Validação do Alerta de Timeout ICMP 

(A fundamentação teórica sobre o mecanismo de monitorização ativa em background e a gestão da estrutura de dados de pacotes pendentes pode ser consultada na @sec-func-alerts).

Para validar a capacidade de monitorização ativa de anomalias na rede, testámos a funcionalidade extra de deteção de timeouts ICMP. O teste consistiu em enviar um ping para um endereço que propositadamente não responde (neste caso, um IP vazio na rede local `10.0.0.99`), executado na interface real da máquina hospedeira.

Comandos:
```
Terminal 1 (Sniffer): sudo python3 main.py -i wlo1 -p ICMP -v
Terminal 2 (Cliente): ping -c 2 10.0.0.99
```

#figure(
  image("imgs/alertas.png", width: 120%),
  caption: [Output do sniffer: monitorização ativa deteta a falta de respostas e gera alertas a vermelho na consola.]
) <fig-alertas>

#figure(
  image("imgs/ping_fail.png", width: 120%),
  caption: [Comando ping resulta em 100% de perda de pacotes.]
)

#figure(
  image("imgs/wireshark34.png", width: 120%),
  caption: [Wireshark captura os pacotes de forma passiva, acrescentando apenas uma nota na coluna Info.]
)


O Wireshark é, por natureza, uma ferramenta de captura passiva. Num cenário de timeout, ele regista os pacotes `Echo (ping) request` a sair e limita-se a colocar a indicação `(no response found!)` no final da linha. Não gera nenhum pop-up, interrupção ou alerta visual destacado para avisar o administrador de sistemas da anomalia. 

Em contraste, o sniffer desenvolvido implementa uma análise de estado ativo (_stateful_). A aplicação não se limita a imprimir o tráfego que passa; uma _thread_ de background monitoriza continuamente a memória interna do programa e, se não detetar o _echo reply_ correspondente num intervalo predefinido (2 segundos), atua proativamente emitindo um `[ALERTA REDE]` explícito na consola. Este teste comprova a utilidade de desenvolver ferramentas focadas não apenas na recolha, mas na monitorização de anomalias em tempo real.


#pagebreak()


// ══════════════════════════════════════════════════════════════
= Análise na Interface Real (Parte B)
// DICA: Descreve o que capturaste na interface wlo1 do teu PC
// e os obstáculos encontrados. O enunciado pede "análise na
// interface real e obstáculos encontrados".

Na Parte B, o sniffer foi executado na interface Wi-Fi real do PC (`wlo1`), capturando tráfego real gerado pelo sistema operativo e pela navegação normal na Internet.

// [INSERIR PRINT do output do sniffer a correr na interface real, mostrando vários protocolos]

== Protocolos Observados
// DICA: Refere os protocolos que apareceram na captura real.
// Da tua captura parteb_dns.json viste:
// - TCP (74%) — ligações HTTPS a vários servidores
// - UDP (19%) — tráfego QUIC (UDP porta 443)
// - DNS (5%) — queries a 193.137.16.65 (DNS da universidade)
// - ARP (1%) — resolução de MACs na rede local
// - ICMPv6 — neighbor discovery
//
// Mostra 2-3 exemplos interessantes do log (ex: DNS query
// para google.com com a resposta).

A captura na interface real revelou um conjunto de protocolos mais diverso e menos controlado do que no CORE. Os protocolos identificados foram:

- *TCP* — protocolo dominante, maioritariamente ligações HTTPS (porta 443) a servidores externos (Google, Microsoft, CDNs). O sniffer identifica corretamente o TCP e os flags, mas não consegue ver o conteúdo devido à encriptação TLS.
- *UDP* — grande parte do tráfego UDP é QUIC (porta 443), o protocolo moderno usado pelo Chrome e Firefox em vez do TCP+TLS clássico. O sniffer identifica-o como UDP genérico.
- *DNS* — queries regulares geradas pelo sistema para resolução de nomes. Foi capturado tráfego mDNS (porta 5353) em broadcast multicast, como mostra o excerto já apresentado na secção de protocolos.
- *ARP* — trocas periódicas de resolução de MACs na rede local entre o PC e o router doméstico.
- *ICMPv6* — mensagens de Neighbor Discovery (Neighbor Solicitation / Advertisement) geradas automaticamente pelo IPv6 para descoberta de nós na rede local.

// [INSERIR PRINT das estatísticas finais mostrando a distribuição de protocolos]

== Diferenças em Relação ao CORE
// DICA: Compara o ambiente CORE com o PC real:
// - No CORE o tráfego é controlado e previsível
// - No PC real há muito tráfego de background (atualizações,
//   telemetria, etc.) que não foi gerado intencionalmente
// - No PC real vês QUIC (UDP 443) que é difícil de reproduzir no CORE
// - No CORE consegues isolar cada protocolo; no PC real
//   aparecem todos misturados

#table(
  columns: (auto, 1fr, 1fr),
  align: (left, left, left),
  table.header([*Aspeto*], [*CORE*], [*Interface real*]),
  [Tráfego], [Controlado e previsível], [Muito ruído de background],
  [Protocolos], [Isoláveis por protocolo], [Todos misturados],
  [HTTP], [Visível em claro (porta 80)], [Encriptado via HTTPS/TLS],
  [DNS], [Difícil sem servidor DNS], [Abundante (queries do SO)],
  [QUIC], [Não reproduzível], [Presente em grande volume],
  [ARP], [Desencadeado manualmente], [Periódico e automático],
)

== Obstáculos Encontrados
// DICA: Menciona as dificuldades reais que encontraste:
// 1. HTTPS/TLS — todo o tráfego web é encriptado, por isso
//    o sniffer vê TCP mas não consegue ver o conteúdo HTTP
// 2. QUIC — muito tráfego moderno usa UDP 443 (QUIC) em vez
//    de TCP 443 — o sniffer identifica como UDP genérico
// 3. Tráfego de background — muito ruído de processos do sistema
//    (telemetria, sincronização, etc.)
// 4. DHCP — difícil de capturar sem forçar uma renovação de IP
//    (o IP já estava atribuído)

Durante a captura na interface real, foram encontrados os seguintes obstáculos:

1. *HTTPS/TLS* — A quase totalidade do tráfego web está encriptada. O sniffer consegue identificar as ligações TCP e os handshakes TLS, mas não consegue ler o conteúdo das mensagens HTTP. Isto limita a utilidade do detetor HTTP na interface real.

2. *QUIC (UDP 443)* — Grande parte do tráfego moderno usa o protocolo QUIC sobre UDP em vez de TCP. O sniffer identifica estes pacotes como UDP genérico, pois o QUIC é encriptado e não tem um cabeçalho fixo que permita identificação por heurística simples.

3. *Tráfego de background* — O sistema operativo gera constantemente tráfego não intencional (telemetria, atualizações automáticas, sincronização de ficheiros, etc.), o que dificulta isolar o tráfego gerado intencionalmente.

4. *DHCP* — Não foi possível capturar tráfego DHCP facilmente porque o IP já estava atribuído. Para forçar uma renovação seria necessário executar `dhclient -r && dhclient wlo1`, o que pode interromper a ligação à rede.

5. *Permissões* — A captura em interface real requer permissões de root. Em sistemas com Secure Boot ativo, pode ser necessário configurar o Scapy para usar o socket raw do sistema.

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Funcionalidades Extras (Opcionais)

Além dos requisitos base, foram implementadas quatro funcionalidades opcionais que enriquecem a capacidade de análise e monitorização do sniffer.

== Medição de RTT ICMP <sec-func-rtt>

O módulo `rtt.py` implementa a medição do tempo de ida e volta (RTT) para pacotes ICMP. O sniffer regista o instante de envio de cada _echo request_ e, ao capturar o _echo reply_ correspondente, calcula a latência.

#figure(
  image("imgs/rtts34.png", width: 100%),
  caption: [Destaque dos valores de RTT calculados em tempo real pela nova funcionalidade.]
) <fig-extra-rtt-inline>

#figure(
  image("imgs/ping223.png", width: 100%),
  caption: [Output do comando ping servindo de referência para validação dos tempos.]
) <fig-extra-rtt-ping>

Como demonstrado na @fig-extra-rtt-inline (destacado pelos retângulos vermelhos), o sniffer apresenta o RTT calculado para cada par de pacotes em tempo real. Por exemplo, para o pacote com `seq=1`, o sniffer mediu `24.782 ms`, enquanto o comando nativo `ping` reportou `25.3 ms` (@fig-extra-rtt-ping). 

Esta correspondência quase exata entre os valores calculados pela nossa funcionalidade e os valores reportados pelo sistema operativo valida a precisão do algoritmo implementado, provando que a gestão de memória e o cálculo diferencial de timestamps estão a funcionar corretamente.

== Alertas de Rede (Monitorização Ativa) <sec-func-alerts>

O sniffer implementa monitorização ativa de anomalias através da deteção de _timeouts_ ICMP. Uma _thread_ de _background_ monitoriza continuamente os pedidos pendentes; se um _echo request_ não obtiver resposta em 2 segundos, é emitido um alerta visual destacado.

#figure(
  image("imgs/alertas34.png", width: 100%),
  caption: [Visualização dos alertas proativos gerados pelo sistema de monitorização ativa.]
) <fig-extra-alertas>

Diferente do Wireshark, que apenas anota a falta de resposta de forma passiva, o sniffer atua proativamente (@fig-extra-alertas), facilitando a deteção imediata de falhas de conectividade ou hosts inacessíveis.

== TCP Flow Tracking <sec-func-tcp>

O módulo `flows.py` rastreia o ciclo de vida das ligações TCP, identificando as transições entre estados (SYN, ESTABLISHED, FIN). Cada mudança de estado é assinalada a verde na consola, permitindo acompanhar o progresso do _handshake_ e do encerramento da ligação.

#figure(
  image("imgs/123j.png", width: 100%),
  caption: [Rastreio de fluxo TCP: identificação visual das fases de estabelecimento e fecho da ligação.]
) <fig-extra-flows>

Conforme evidenciado pelos destaques na @fig-extra-flows, o sniffer identificou com precisão os marcos da ligação efetuada entre `192.168.1.171` e `34.223.124.45`:

1. *TCP SYN*: A deteção do primeiro pacote de sincronização que marca a intenção de abrir uma nova ligação.
2. *TCP SYN-ACK*: A interceção da resposta do servidor, confirmando a disponibilidade para a ligação.
3. *TCP ESTABLISHED*: A conclusão do _Three-way Handshake_, indicando que a sessão está ativa para troca de dados.
4. *TCP FIN*: O reconhecimento do encerramento da ligação após a transferência de dados.

Esta capacidade de _tracking_ transforma a captura de pacotes isolados numa análise de sessões estruturada, permitindo ao utilizador visualizar a "saúde" das ligações e identificar handshakes incompletos ou encerramentos forçados de forma imediata.

== Estatísticas Periódicas

A funcionalidade de estatísticas periódicas, ativada através da _flag_ `--stats-interval N`, introduz uma capacidade de monitorização em tempo real indispensável para capturas de longa duração. Esta funcionalidade é suportada por uma _thread_ secundária de _background_ que, sem interromper o fluxo de captura principal, acede aos contadores globais da aplicação para calcular métricas de desempenho instantâneas.

O relatório periódico apresenta ao utilizador:
- *Throughput* de pacotes (pkts/s);
- Largura de banda instantânea (KB/s);
- Resumo da distribuição de protocolos no intervalo específico;
- Estado atual dos fluxos TCP ativos.

Esta implementação permite uma análise dinâmica da "saúde" da interface de rede, possibilitando a identificação visual de picos de tráfego ou alterações no perfil de comunicação (ex: aumento súbito de tráfego UDP) sem a necessidade de encerrar a sessão de captura para consultar os totais acumulados. Trata-se de uma ferramenta de diagnóstico proativo que complementa o sumário estatístico final apresentado no encerramento do programa.

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Limitações
// DICA: Sê honesto sobre o que o sniffer não consegue fazer.
// O enunciado pede "limitações da aplicação desenvolvida".
//
// Sugestões:
// - Não consegue desencriptar HTTPS/TLS — vê o TCP mas não
//   o conteúdo das mensagens
// - QUIC (UDP 443) é identificado como UDP genérico, não como
//   protocolo específico
// - HTTP detetado apenas na porta 80/8080 heuristicamente —
//   HTTP em portas não standard pode não ser detetado
// - Não suporta captura em múltiplas interfaces simultaneamente
// - O FlowTracker pode perder o estado de ligações que já
//   estavam ativas quando o sniffer arrancou
// - No CORE, sem acesso à internet, DNS e DHCP não são
//   facilmente reproduzíveis

O sniffer desenvolvido cobre os requisitos do trabalho, mas tem algumas limitações inerentes à abordagem adotada:

- *HTTPS/TLS* — O sniffer identifica as ligações TCP e os handshakes TLS, mas não consegue desencriptar o conteúdo das mensagens. Na prática, a maioria do tráfego web atual é encriptado, pelo que o detetor de HTTP tem utilidade limitada na interface real.

- *QUIC* — O protocolo QUIC (usado pelo Chrome, Firefox e muitas aplicações modernas) corre sobre UDP porta 443 e é encriptado. O sniffer identifica-o como UDP genérico, não como QUIC específico.

- *HTTP em portas não standard* — A deteção de HTTP é feita pela combinação de porta 80/8080 com heurística no payload (verifica se começa com `GET`, `POST`, `HTTP/`, etc.). HTTP em portas não standard (ex: 8000, 3000) pode não ser detetado se o payload não for imediatamente identificável.

- *Captura numa única interface* — O sniffer só consegue escutar uma interface de rede de cada vez. Para monitorizar simultaneamente múltiplas interfaces seria necessário lançar várias instâncias em paralelo.

- *Estado de ligações TCP preexistentes* — O `FlowTracker` só consegue rastrear ligações TCP que são iniciadas (SYN) depois do sniffer arrancar. Ligações TCP já estabelecidas quando o sniffer começa aparecem como tráfego TCP genérico, sem estado associado.

- *DNS no CORE* — A topologia CORE não tem servidor DNS configurado, pelo que o protocolo DNS foi capturado e validado exclusivamente na interface real (Parte B).

- *DHCP* — Por razões semelhantes, o DHCP é difícil de capturar sem forçar uma renovação de IP, o que implica interromper momentaneamente a ligação à rede.

#pagebreak()


// ══════════════════════════════════════════════════════════════
= Conclusão
// DICA: 2-3 parágrafos. Resume o que foi feito, o que
// aprendeste sobre os protocolos ao implementar o sniffer,
// e o que melhorarias com mais tempo.
//
// Sugestão de estrutura:
// § 1: O que foi desenvolvido e os objetivos cumpridos
// § 2: O que aprendeste (como os protocolos funcionam na
//      prática, diferença entre ambiente controlado e real)
// § 3: Trabalho futuro (suporte TLS, interface gráfica,
//      captura multi-interface, etc.)

Este trabalho resultou no desenvolvimento de um packet sniffer funcional em Python com Scapy, capaz de capturar, identificar e registar tráfego de rede em tempo real. Foram cumpridos todos os requisitos do enunciado: captura em interface emulada (CORE) e real (Wi-Fi), identificação dos protocolos ARP, ICMP, TCP, UDP, HTTP e DNS, filtros por protocolo, IP, MAC, porta e expressão BPF, modos de output live e log simultâneos em três formatos (JSON, CSV, TXT), e funcionalidades opcionais de medição de RTT, tracking de fluxos TCP e estatísticas periódicas.

A implementação do sniffer aprofundou a compreensão prática dos protocolos estudados nas aulas teóricas. Ao ter de identificar pacotes camada a camada, tornou-se claro como cada protocolo tem uma estrutura bem definida e como os protocolos se encadeiam (ex: HTTP sobre TCP sobre IPv4 sobre Ethernet). A transição para a interface real evidenciou a diferença entre um ambiente controlado e a complexidade do tráfego real: a prevalência de TLS/HTTPS, o crescimento do QUIC, e o ruído constante de processos de background mostram que uma rede real é muito mais heterogénea do que o CORE sugere.

Com mais tempo, seria interessante adicionar suporte a HTTPS com integração de chaves TLS para desencriptação (possível com `mitmproxy` ou exportação de chaves do browser), identificação de QUIC como protocolo específico, uma interface gráfica simples com gráficos de tráfego em tempo real, e suporte a captura simultânea em múltiplas interfaces.

