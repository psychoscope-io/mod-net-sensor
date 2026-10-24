#!/usr/bin/env python3
"""Gera um pcap sintetico (Ethernet) para o e2e e imprime o numero de eventos esperado
com a politica 'interesting'. Uso: gen_pcap.py <saida.pcap> [--repeat N] [--filler M]

--repeat N repete o conjunto N vezes (instantes deslocados em 10000 s por copia) e --filler M
acrescenta, por copia, M pacotes de dados TCP e UDP que a politica 'interesting' descarta:
servem de carga para o benchmark (make bench). Sem opcoes, a saida e a do e2e.

Trafego benigno + trafego malicioso que deve gerar EXATAMENTE 10 alertas:
  net.scan.syn x1, net.dns.nxdomain_burst x1, net.dns.tunnel x1, net.bruteforce.auth x1,
  net.icmp.sweep x1, net.beacon x1, net.dns.rate x1, net.tls.suspicious x3
  (SNI IP literal, versao TLS1.0 e SNI IP literal em ClientHello FRAGMENTADO em 2 segmentos TCP).
"""
import argparse, random, socket, ssl, struct

def mac(n): return bytes([2, 0, 0, 0, 0, n])
def eth(l3, ethertype, vlan=None):
    h = mac(2) + mac(1)
    if vlan is not None:
        h += struct.pack("!HH", 0x8100, vlan)
    return h + struct.pack("!H", ethertype) + l3
def ip4(proto, payload, src="10.0.0.1", dst="10.0.0.2"):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload
def ip6(nh, payload, src="fe80::1", dst="fe80::2"):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), nh, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload
def udp(sp, dp, data): return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
def tcp(sp, dp, flags, data=b"", seq=0): return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, 65535, 0, 0) + data

def qname(n): return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
def dns_query(name, qtype=1): return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", qtype, 1)
def dns_resp(name, rcode, ips):
    m = struct.pack("!HHHHHH", 0x1234, 0x8180 | rcode, 1, len(ips), 0, 0) + qname(name) + struct.pack("!HH", 1, 1)
    for ip in ips:
        m += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return m

def client_hello(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s = ctx.wrap_bio(inc, out, server_hostname=host)
    try:
        s.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()

def raw_hello(sni=None, versions=(), legacy=0x0303, pad_before_sni=0):
    """ClientHello montado a mao: permite SNI IP literal, TLS 1.0 e extensao de padding
    antes do SNI (para o SNI cair no 2o segmento quando o registro e fragmentado)."""
    def ext(t, body): return struct.pack("!HH", t, len(body)) + body
    exts = b""
    if pad_before_sni:
        exts += ext(21, b"\0" * pad_before_sni)
    if sni:
        exts += ext(0, struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode())
    if versions:
        exts += ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack("!H", v) for v in versions))
    ch = (struct.pack("!H", legacy) + b"\x07" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
          + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

T0 = 1_700_000_000
packets, expected, auto_n = [], 0, 0
def add(frame, counts, at=None):
    """at=None: instante automatico (100 ms entre pacotes automaticos); senao segundos desde T0."""
    global expected, auto_n
    if at is None:
        at = auto_n * 0.1
        auto_n += 1
    packets.append((at, frame))
    expected += counts

SYN, RST, ACK, PSH = 0x02, 0x04, 0x10, 0x08
add(eth(ip4(17, udp(51000, 53, dns_query("Example.com"))), 0x0800), 1)
add(eth(ip4(17, udp(53, 51000, dns_resp("example.com", 0, ["93.184.216.34"])), "10.0.0.2", "10.0.0.1"), 0x0800), 1)
add(eth(ip4(17, udp(53, 51001, dns_resp("nao-existe.invalid", 3, [])), "10.0.0.2", "10.0.0.1"), 0x0800), 1)
add(eth(ip6(17, udp(51002, 53, dns_query("v6.example.org", 28))), 0x86dd), 1)
add(eth(ip4(17, udp(51003, 53, dns_query("vlan.example.net"))), 0x0800, vlan=100), 1)
add(eth(ip4(6, tcp(52000, 443, PSH | ACK, client_hello("secure.example.com"))), 0x0800), 1)
for port in range(1, 6):                       # varredura SYN + respostas RST
    add(eth(ip4(6, tcp(40000, port, SYN), "10.0.0.66", "10.0.0.2"), 0x0800), 1)
    add(eth(ip4(6, tcp(port, 40000, RST | ACK), "10.0.0.2", "10.0.0.66"), 0x0800), 1)
add(eth(ip4(1, bytes([3, 3, 0, 0]) + b"\0" * 4, "10.0.0.2", "10.0.0.66"), 0x0800), 1)   # ICMP port unreachable
add(eth(ip4(6, tcp(52000, 80, PSH | ACK, b"GET / HTTP/1.1\r\n\r\n")), 0x0800), 0)       # dados TCP: ignorado
add(eth(ip4(17, udp(1000, 2000, b"ruido")), 0x0800), 0)                                 # UDP generico: ignorado
add(eth(b"\0" * 28, 0x0806), 0)                                                          # ARP: nao suportado

# --- trafego malicioso (deve gerar exatamente 10 alertas) ---
rng = random.Random(1)
for port in range(1000, 1025):                 # varredura vertical: 25 portas de 10.0.0.2 por 10.0.0.77
    add(eth(ip4(6, tcp(41000, port, SYN), "10.0.0.77", "10.0.0.2"), 0x0800), 1)
for i in range(12):                            # rajada de NXDOMAIN (DGA) para o cliente 10.0.0.1
    d = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12)) + ".example"
    add(eth(ip4(17, udp(53, 52000 + i, dns_resp(d, 3, [])), "10.0.0.2", "10.0.0.1"), 0x0800), 1)
B32 = "abcdefghijklmnopqrstuvwxyz234567"
for i in range(6):                             # tunel DNS: rotulos base32 de 48 chars sob t.exfil.example
    label = "".join(rng.choice(B32) for _ in range(48))
    add(eth(ip4(17, udp(53000 + i, 53, dns_query(label + ".t.exfil.example")), "10.0.0.88", "10.0.0.2"), 0x0800), 1)

for i in range(12):                            # forca bruta SSH: 12 conexoes (portas de origem distintas) a 10.0.0.2:22
    add(eth(ip4(6, tcp(55000 + i, 22, SYN), "10.0.0.99", "10.0.0.2"), 0x0800), 1)
for i in range(1, 26):                         # varredura ICMP: echo request de 10.0.0.55 a 25 hosts
    add(eth(ip4(1, bytes([8, 0, 0, 0, 0, 1, 0, i]), "10.0.0.55", "10.0.5.%d" % i), 0x0800), 1)
add(eth(ip4(6, tcp(53001, 443, PSH | ACK, raw_hello("93.184.216.34", versions=(0x0304,))), "10.0.0.31", "10.0.0.2"), 0x0800), 1)   # SNI = IP
add(eth(ip4(6, tcp(53002, 443, PSH | ACK, raw_hello("legacy.example.com", legacy=0x0301)), "10.0.0.32", "10.0.0.2"), 0x0800), 1)  # TLS1.0
frag = raw_hello("198.51.100.77", versions=(0x0304, 0x0303), pad_before_sni=700)   # SNI IP no FIM do registro
cut = 400
add(eth(ip4(6, tcp(53003, 443, PSH | ACK, frag[:cut], seq=1000), "10.0.0.33", "10.0.0.2"), 0x0800), 1)
add(eth(ip4(6, tcp(53003, 443, PSH | ACK, frag[cut:], seq=1000 + cut), "10.0.0.33", "10.0.0.2"), 0x0800), 0)
for i in range(10):                            # beaconing: SYN a cada ~30 s (jitter +-2 s) de 10.0.0.44 a 203.0.113.50:443
    add(eth(ip4(6, tcp(54000 + i, 443, SYN), "10.0.0.44", "203.0.113.50"), 0x0800), 1, at=100 + 30 * i + rng.uniform(-2, 2))
for i in range(220):                           # pico de DNS: 220 consultas em ~9 s de 10.0.0.60
    add(eth(ip4(17, udp(56000 + i, 53, dns_query("h%d.rate.example" % (i % 40))), "10.0.0.60", "10.0.0.2"), 0x0800), 1, at=500 + i * 0.04)

ap = argparse.ArgumentParser(description="Gera um pcap sintetico para o e2e e para o benchmark.")
ap.add_argument("saida")
ap.add_argument("--repeat", type=int, default=1, help="copias do conjunto de pacotes")
ap.add_argument("--filler", type=int, default=0, help="pacotes descartados pela politica, por copia")
args = ap.parse_args()

COPY_SPAN = 10_000                             # segundos entre copias: cada copia fica depois da anterior
all_packets = []
for r in range(args.repeat):
    all_packets += [(at + r * COPY_SPAN, p) for at, p in packets]
    for j in range(args.filler):               # dados TCP e UDP generico, de hosts distintos
        src = "10.1.%d.%d" % (j // 250 % 250, j % 250 + 1)
        body = (b"x" * 100) if j % 2 else (b"y" * 400)
        l4 = tcp(30000 + j % 1000, 8080, PSH | ACK, body) if j % 3 else udp(30000 + j % 1000, 9999, body)
        all_packets.append((r * COPY_SPAN + j * 0.001, eth(ip4(6 if j % 3 else 17, l4, src, "10.0.0.2"), 0x0800)))

all_packets.sort(key=lambda x: x[0])           # o motor espera eventos em ordem cronologica
with open(args.saida, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for at, p in all_packets:
        t = T0 * 1_000_000 + int(round(at * 1_000_000))
        f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)
print(expected * args.repeat)
