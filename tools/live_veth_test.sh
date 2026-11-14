#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cleanup() {
    sudo ip link set dev veth_ztm0 xdp off 2>/dev/null || true
    sudo ip netns del ztm_gen 2>/dev/null || true
    sudo ip link del veth_ztm0 2>/dev/null || true
}
trap cleanup EXIT

echo "[1/4] Компиляция eBPF XDP объекта (xdp_zero_shield.c)..."
clang -O2 -g -target bpf -c xdp_shield/xdp_zero_shield.c -o xdp_shield/xdp_zero_shield.o

echo "[2/4] Поднятие изолированной пары veth_ztm0 <-> veth_ztm1 (netns: ztm_gen)..."
cleanup
sudo ip netns add ztm_gen
sudo ip link add veth_ztm0 type veth peer name veth_ztm1
sudo ip link set veth_ztm1 netns ztm_gen

sudo ip link set veth_ztm0 up
sudo ip -n ztm_gen link set lo up
sudo ip -n ztm_gen link set veth_ztm1 up

echo "[3/4] Подключение XDP программ (xdp_zero_shield_prog + xdp_peer_pass)..."
sudo ip -n ztm_gen link set dev veth_ztm1 xdp obj xdp_shield/xdp_zero_shield.o sec xdp_peer
sudo ip link set dev veth_ztm0 xdp obj xdp_shield/xdp_zero_shield.o sec xdp

echo "[4/4] Генерация живого трафика (Clean TLS/HTTP + HTTP Smuggling + TLS Record Splitting + TCP Null)..."
sudo ip netns exec ztm_gen python3 - << 'PYEOF'
import socket, struct

def frame(tcp_flags, dst_port, payload):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0, b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01")
    tcp = struct.pack("!HHIIBBHHH", 44444, dst_port, 1, 1, 0x50, tcp_flags, 65535, 0, 0)
    return eth + ip + tcp + payload

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("veth_ztm1", 0))

clean_tls   = frame(0x18, 443, b"\x16\x03\x03\x00\x60" + b"\x01" * 20) # Normal TLS (rlen=96)
clean_http  = frame(0x18, 80,  b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n")
smuggling   = frame(0x18, 80,  b"POST /  chunked\r\n\r\n")
tls_split   = frame(0x18, 443, b"\x16\x03\x01\x00\x05" + b"\x01" * 16) # Split TLS (rlen=5 < 40!)
tcp_null    = frame(0x00, 80,  b"A" * 20)

for _ in range(1000):
    s.send(clean_tls)
    s.send(clean_http)
    s.send(smuggling)
    s.send(tls_split)
    s.send(tcp_null)
s.close()
print("[*] Отправлено 5000 живых кадров через драйвер veth!")
PYEOF

sleep 0.2
echo "=== ЖИВЫЕ СЧЕТЧИКИ XDP STATS_MAP (PER-CPU) ==="
sudo bpftool map dump name stats_map || true
