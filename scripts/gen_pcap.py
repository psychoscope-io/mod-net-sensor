#!/usr/bin/env python3
"""Gera um pcap sintetico (Ethernet) para o e2e e imprime o numero de eventos esperado
com a politica 'interesting'. Uso: gen_pcap.py <saida.pcap>"""
import socket, ssl, struct, sys

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
def tcp(sp, dp, flags, data=b""): return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0) + data

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

packets, expected = [], 0
def add(frame, counts):
    global expected
    packets.append(frame)
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

with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(p), len(p)) + p)
print(expected)
