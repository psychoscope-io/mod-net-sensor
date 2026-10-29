#!/usr/bin/env python3
"""Gera um pcap SINTETICO grande de trafego variado (muitas origens e destinos, DNS, handshakes
TCP e ClientHellos com SNIs distintos) ou uma tempestade de alertas, para medir a vazao do servico
(scripts/bench_replay.sh). Escreve em fluxo, em ordem de tempo, sem montar tudo na memoria.
Uso: gen_traffic_pcap.py SAIDA --modo variado|tempestade-scan|tempestade-nxdomain --n N

variado            N eventos: ~50% consultas DNS, ~40% handshakes TCP (SYN e SYN-ACK) e ~10%
                   ClientHello, de 5000 origens para 200 destinos, 256 SNIs. Nenhum alerta
                   esperado (so o que for por acaso).
tempestade-scan    N origens distintas, cada uma varrendo 25 portas de um destino (um alerta
                   net.scan.syn por origem).
tempestade-nxdomain N clientes distintos, cada um recebendo 12 respostas NXDOMAIN para nomes
                   diferentes (um alerta net.dns.nxdomain_burst por cliente).
Imprime o numero de eventos que o sensor deve emitir (politica `interesting`).
Enderecos de documentacao e privados; nenhum trafego real.
"""
import argparse, random, socket, struct, sys

def ip4(proto, payload, src, dst):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload
def tcp(sp, dp, flags, data=b""): return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0) + data
def udp(sp, dp, data): return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
ETH = bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + struct.pack("!H", 0x0800)
def frame(l3): return ETH + l3
SYN, RST, ACK, PSH = 0x02, 0x04, 0x10, 0x08

def qname(n): return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"
def dns_query(i, name): return struct.pack("!HHHHHH", i & 0xFFFF, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", 1, 1)
def dns_nxdomain(i, name): return struct.pack("!HHHHHH", i & 0xFFFF, 0x8183, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", 1, 1)

def client_hello(sni):
    host = struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode()
    exts = struct.pack("!HH", 0, len(host)) + host
    ch = (struct.pack("!H", 0x0303) + b"\x07" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
          + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

class Out:
    def __init__(self, path, t0=1_700_000_000):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.t0, self.events = t0, 0
    def add(self, at, pkt, counts=True):
        t = self.t0 * 1_000_000 + int(round(at * 1_000_000))
        self.f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(pkt), len(pkt)) + pkt)
        self.events += counts
    def close(self): self.f.close()

def variado(out, n, dt):
    rng = random.Random(1)
    hellos = [client_hello("site%d.example.com" % i) for i in range(256)]
    t = 0.0
    while out.events < n:
        r = rng.randrange(100)
        src = "10.%d.%d.%d" % (1 + rng.randrange(20), rng.randrange(250), 1 + rng.randrange(250))   # ~1,2 milhao de origens possiveis
        if r < 50:
            out.add(t, frame(ip4(17, udp(40000 + rng.randrange(20000), 53, dns_query(rng.randrange(65536), "h%d.example.com" % rng.randrange(4096))), src, "10.0.0.53")))
        else:
            dst = "203.0.113.%d" % (1 + rng.randrange(200))
            sp = 40000 + rng.randrange(20000)
            if r < 90:
                out.add(t, frame(ip4(6, tcp(sp, 443, SYN), src, dst)))
                t += dt
                out.add(t, frame(ip4(6, tcp(443, sp, SYN | ACK), dst, src)))
            else:
                out.add(t, frame(ip4(6, tcp(sp, 443, PSH | ACK, hellos[rng.randrange(256)]), src, dst)))
        t += dt

def tempestade_scan(out, n, dt):
    t = 0.0
    for k in range(n):
        src = "10.%d.%d.%d" % (100 + k // 62500, k // 250 % 250, k % 250 + 1)
        for port in range(1, 26):
            out.add(t, frame(ip4(6, tcp(41000, port, SYN), src, "198.51.100.7")))
            t += dt

def tempestade_nxdomain(out, n, dt):
    t = 0.0
    for k in range(n):
        client = "10.%d.%d.%d" % (100 + k // 62500, k // 250 % 250, k % 250 + 1)
        for j in range(12):
            out.add(t, frame(ip4(17, udp(53, 52000 + j, dns_nxdomain(j, "x%dq%d.example.com" % (k, j))), "198.51.100.53", client)))
            t += dt

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Gera um pcap sintetico grande para scripts/bench_replay.sh.")
    ap.add_argument("saida")
    ap.add_argument("--modo", choices=["variado", "tempestade-scan", "tempestade-nxdomain"], default="variado")
    ap.add_argument("--n", type=int, default=500_000, help="eventos (variado) ou origens/clientes (tempestade)")
    ap.add_argument("--dt", type=float, default=0.00002, help="segundos entre pacotes no tempo do pcap")
    a = ap.parse_args()
    o = Out(a.saida)
    {"variado": variado, "tempestade-scan": tempestade_scan, "tempestade-nxdomain": tempestade_nxdomain}[a.modo](o, a.n, a.dt)
    o.close()
    print(o.events)
