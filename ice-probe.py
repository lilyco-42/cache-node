#!/usr/bin/env python3
"""ice-probe —— ICE 服务器连通性探测（STUN Binding + TCP 可达）。

用法: python3 ice-probe.py <server-ip> [stun-port]
"""
import os
import socket
import struct
import sys


def stun_probe(ip: str, port: int = 3478) -> str:
    tid = os.urandom(12)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    try:
        s.sendto(struct.pack(">HHI", 0x0001, 0, 0x2112A442) + tid, (ip, port))
        data, _ = s.recvfrom(2048)
    except (socket.timeout, OSError) as e:
        return f"UDP FAIL: {type(e).__name__}"
    finally:
        s.close()
    i = 20
    while i + 4 <= len(data):
        t, ln = struct.unpack(">HH", data[i:i + 4])
        if t == 0x0020 and ln >= 8:
            px = struct.unpack(">H", data[i + 6:i + 8])[0] ^ 0x2112
            ix = struct.unpack(">I", data[i + 8:i + 12])[0] ^ 0x2112A442
            ipx = ".".join(str((ix >> sh) & 0xFF) for sh in (24, 16, 8, 0))
            return f"UDP STUN OK: mapped {ipx}:{px}"
        i += 4 + ln + ((4 - ln % 4) % 4)
    return "UDP OK (no xor-mapped attr)"


def tcp_probe(ip: str, port: int = 3478) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=5)
        s.close()
        return "TCP OK"
    except OSError as e:
        return f"TCP FAIL: {type(e).__name__}"


if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    print(f"{ip}:{port}  {stun_probe(ip, port)}  |  {tcp_probe(ip, port)}")
