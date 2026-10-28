#!/usr/bin/env python3
"""Gera os pcaps SINTETICOS do catalogo (so enderecos de documentacao, RFC 5737, e nomes de
exemplo; nenhum trafego real). Uso: gen_fp_pcap.py [raiz-do-testdata]

testdata/falsos-positivos/ (o alerta e indevido; os .esperado e .ajuste ao lado dizem o que
ainda dispara com os limiares padrao e o que o silencia):
  beacon-keepalive     aplicativo legitimo que reabre a conexao a cada ~30 s (net.beacon)
  nxdomain-srv-apt     consultas SRV _https._tcp.* que voltam NXDOMAIN, como o apt (nxdomain_burst)
  scan-web-navegador   navegador que abre 40 conexoes na 443 com handshake completo (net.scan.syn)
  tls-sni-azure-blob   SNI de armazenamento de nuvem com rotulo parecido com aleatorio (tls)
testdata/verdadeiros-positivos/ (o alerta TEM de disparar; guarda o que um ajuste nao pode perder):
  scan-nmap-vertical           100 portas de um host, algumas com RST (net.scan.syn, vertical)
  scan-horizontal-443          150 hosts na 443 que nao respondem (net.scan.syn, horizontal)
  nxdomain-dga-com-srv         DGA misturado a consultas SRV (net.dns.nxdomain_burst)
"""
import random, socket, struct, sys, os

def ip4(proto, payload, src, dst):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload
def tcp(sp, dp, flags, data=b""): return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0) + data
def udp(sp, dp, data): return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data

SYN, RST, ACK, PSH = 0x02, 0x04, 0x10, 0x08

def qname(n): return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
def dns_nxdomain(name):
    return struct.pack("!HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", 1, 1)

def client_hello(sni):
    """ClientHello TLS 1.2 minimo com SNI."""
    host = struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode()
    exts = struct.pack("!HH", 0, len(host)) + host
    ch = (struct.pack("!H", 0x0303) + b"\x07" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
          + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
def eth(l3): return bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + struct.pack("!H", 0x0800) + l3

def write_pcap(path, packets, t0=1_700_000_000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for at, p in sorted(packets, key=lambda x: x[0]):
            t = t0 * 1_000_000 + int(round(at * 1_000_000))
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)

CLIENT, RESOLVER = "192.0.2.10", "198.51.100.53"

def beacon_keepalive():
    rng = random.Random(7)
    return [(30 * i + rng.uniform(-1, 1), eth(ip4(6, tcp(50000 + i, 443, SYN), CLIENT, "198.51.100.7")))
            for i in range(12)]

def nx_resp(at, name):
    return (at, eth(ip4(17, udp(53, 51000, dns_nxdomain(name)), RESOLVER, CLIENT)))

def srv_lookups(n, start=0.0):
    return [nx_resp(start + i * 0.5, "_https._tcp.host%d.example.com" % i) for i in range(n)]

def nxdomain_srv_apt(): return srv_lookups(30)

def nxdomain_dga_com_srv():
    rng = random.Random(3)
    dga = [nx_resp(20 + i * 0.5, "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12)) + ".example.com")
           for i in range(12)]
    return srv_lookups(30) + dga

def scan_web_navegador():
    """40 hosts na 443 a cada 0,1 s, cada um respondendo SYN-ACK 50 ms depois, e uma sonda ao fim."""
    pk = []
    for h in range(1, 41):
        host = "203.0.113.%d" % h
        pk.append((h * 0.1, eth(ip4(6, tcp(50000 + h, 443, SYN), CLIENT, host))))
        pk.append((h * 0.1 + 0.05, eth(ip4(6, tcp(443, 50000 + h, SYN | ACK), host, CLIENT))))
    pk.append((8.0, eth(ip4(6, tcp(50100, 443, SYN), CLIENT, "203.0.113.200"))))  # avalia a janela depois da rajada
    return pk

def scan_horizontal_443():
    """150 hosts na 443 a cada 0,05 s e nenhum responde."""
    return [(h * 0.05, eth(ip4(6, tcp(50000 + h, 443, SYN), CLIENT, "203.0.113.%d" % (h % 250 + 1)))) for h in range(1, 151)]

def scan_nmap_vertical():
    """100 portas de um host em 2 s; as fechadas respondem RST|ACK."""
    pk = []
    for i, port in enumerate(range(1, 101)):
        at = i * 0.02
        pk.append((at, eth(ip4(6, tcp(41000, port, SYN), CLIENT, "198.51.100.7"))))
        if port % 3:
            pk.append((at + 0.01, eth(ip4(6, tcp(port, 41000, RST | ACK), "198.51.100.7", CLIENT))))
    return pk

def tls_sni_azure_blob():
    return [(0.0, eth(ip4(6, tcp(50200, 443, PSH | ACK, client_hello("productionresultssa8.blob.core.example.net")),
                          CLIENT, "203.0.113.20")))]

CASES = {
    "falsos-positivos": {"beacon-keepalive": beacon_keepalive, "nxdomain-srv-apt": nxdomain_srv_apt,
                         "scan-web-navegador": scan_web_navegador, "tls-sni-azure-blob": tls_sni_azure_blob},
    "verdadeiros-positivos": {"scan-nmap-vertical": scan_nmap_vertical, "scan-horizontal-443": scan_horizontal_443,
                              "nxdomain-dga-com-srv": nxdomain_dga_com_srv},
}

if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "testdata")
    for group, cases in CASES.items():
        os.makedirs(os.path.join(root, group), exist_ok=True)
        for name, build in cases.items():
            write_pcap(os.path.join(root, group, name + ".pcap"), build())
