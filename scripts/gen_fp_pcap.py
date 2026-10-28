#!/usr/bin/env python3
"""Gera os pcaps SINTETICOS de falso positivo de testdata/falsos-positivos/ (so enderecos de
documentacao, RFC 5737; nenhum trafego real). Uso: gen_fp_pcap.py [diretorio]

beacon-keepalive: um aplicativo legitimo reabre a conexao com o mesmo servidor a cada ~30 s
(atualizacao periodica), o que a regra net.beacon le como beaconing. E o falso positivo
conhecido do roadmap; os arquivos .esperado e .ajuste ao lado dizem o que se espera dele.
"""
import random, socket, struct, sys, os

def ip4(proto, payload, src, dst):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + payload
def tcp(sp, dp, flags): return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0)
def eth(l3): return bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + struct.pack("!H", 0x0800) + l3

def write_pcap(path, packets, t0=1_700_000_000):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for at, p in sorted(packets, key=lambda x: x[0]):
            t = t0 * 1_000_000 + int(round(at * 1_000_000))
            f.write(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(p), len(p)) + p)

def beacon_keepalive():
    rng = random.Random(7)
    return [(30 * i + rng.uniform(-1, 1), eth(ip4(6, tcp(50000 + i, 443, 0x02), "192.0.2.10", "198.51.100.7")))
            for i in range(12)]

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "testdata", "falsos-positivos")
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, "beacon-keepalive.pcap"), beacon_keepalive())
