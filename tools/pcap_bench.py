#!/usr/bin/env python3
"""
Zero-Timing Manifesto v1.1.0-beta — Offline PCAP & Synthetic Threat Replay Benchmark
Прогон реальных .pcap дампов или синтетического микса (TLS/HTTP + аномальные зонды/Flood)
через скомпилированную C-ABI библиотеку libzero_cisco_daq.so с замером p50/p95/p99/p99.9.
"""
import argparse
import ctypes
import os
import random
import struct
import subprocess
import sys
import time

SO_PATH = "cisco_daq_plugin/libzero_cisco_daq.so"
SRC_PATH = "cisco_daq_plugin/lib.rs"

VERDICT_LABELS = {
    0: "DROP",
    1: "PASS",
    2: "DECEPTION_TRAP",
    3: "MTD_MUTATE",
}


def ensure_shared_lib():
    if not os.path.exists(SO_PATH):
        print(f"[*] Компиляция {SO_PATH} из {SRC_PATH}...")
        subprocess.run(
            ["rustc", "--crate-type", "cdylib", "-C", "panic=abort", "-O", SRC_PATH, "-o", SO_PATH],
            check=True,
        )


def read_pcap_packets(pcap_path: str, limit: int = 100_000):
    packets = []
    with open(pcap_path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            raise ValueError("Некорректный заголовок PCAP файла")
        magic = struct.unpack("<I", global_hdr[:4])
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        while len(packets) < limit:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            _, _, incl_len, _ = struct.unpack(f"{endian}IIII", pkt_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append(data)
    return packets


def build_tcp_frame(payload: bytes, dst_port: int = 443, ttl: int = 64) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_total_len = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total_len, 1, 0, ttl, 6, 0,
        b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01"
    )
    tcp = struct.pack("!HHIIBBHHH", 54321, dst_port, 1, 1, 0x50, 0x18, 65535, 0, 0)
    return eth + ipv4 + tcp + payload


def generate_synthetic_mix(count: int = 100_000):
    clean_http = build_tcp_frame(b"GET /api/v1/market/depth HTTP/1.1\r\nHost: exchange.local\r\n\r\n", 80)
    clean_tls = build_tcp_frame(b"\x16\x03\x01\x00\x40\x01\x00\x00\x3c\x03\x03" + b"\x12" * 53, 443)
    malformed_short = b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x08\x00\x45\x00\x00\x10" + os.urandom(20)
    bad_proto = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45\x00\x00\x40" + b"\x00" * 56

    ttl_spoof_probe = build_tcp_frame(b"GET /admin HTTP/1.1\r\nHost: exchange.local\r\n\r\n", 80, ttl=11)
    pool = [clean_http, clean_tls, clean_http, clean_tls, ttl_spoof_probe, malformed_short]
    return [random.choice(pool) for _ in range(count)]


def percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    idx = min(int(len(sorted_vals) * pct / 100.0), len(sorted_vals) - 1)
    return sorted_vals[idx]


def main():
    parser = argparse.ArgumentParser(description="Zero-Timing Offline PCAP & Threat Replay Benchmark")
    parser.add_argument("--pcap", type=str, default=None, help="Путь к реальному .pcap файлу (опционально)")
    parser.add_argument("--count", type=int, default=100_000, help="Количество пакетов для прогона (по умолчанию 100 000)")
    args = parser.parse_args()

    ensure_shared_lib()
    lib = ctypes.CDLL(os.path.abspath(SO_PATH))
    lib.zero_cisco_inspect_frame.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    lib.zero_cisco_inspect_frame.restype = ctypes.c_uint32
    lib.zero_cisco_init()

    if args.pcap:
        print(f"[*] Загрузка реального дампа PCAP: {args.pcap} (лимит {args.count} пакетов)...")
        packets = read_pcap_packets(args.pcap, args.count)
    else:
        print(f"[*] Генерация синтетического микса (TLS 1.3 / HTTP / Malformed Flood): {args.count} пакетов...")
        packets = generate_synthetic_mix(args.count)

    if not packets:
        print("[!] Нет пакетов для анализа.")
        sys.exit(1)

    c_buffers = [((ctypes.c_uint8 * len(p)).from_buffer_copy(p), len(p)) for p in packets]

    for buf, ln in c_buffers[:1000]:
        lib.zero_cisco_inspect_frame(buf, ln)

    latencies_ns = []
    verdict_stats = {}
    inspect_fn = lib.zero_cisco_inspect_frame
    now_ns = time.perf_counter_ns

    t_start = now_ns()
    for buf, ln in c_buffers:
        t0 = now_ns()
        v = inspect_fn(buf, ln)
        t1 = now_ns()
        latencies_ns.append(t1 - t0)
        verdict_stats[v] = verdict_stats.get(v, 0) + 1
    t_total_sec = (now_ns() - t_start) / 1e9

    latencies_ns.sort()
    mpps = (len(packets) / t_total_sec) / 1e6

    report = []
    report.append("=" * 62)
    report.append(f" ZERO-TIMING C-ABI REPLAY REPORT ({len(packets):,} packets)")
    report.append("=" * 62)
    report.append(f" Total Wall Time   : {t_total_sec:.4f} s ({mpps:.2f} Mpps incl. Python FFI)")
    report.append(f" Latency p50       : {percentile(latencies_ns, 50):>6} ns")
    report.append(f" Latency p95       : {percentile(latencies_ns, 95):>6} ns")
    report.append(f" Latency p99       : {percentile(latencies_ns, 99):>6} ns")
    report.append(f" Latency p99.9     : {percentile(latencies_ns, 99.9):>6} ns")
    report.append("-" * 62)
    report.append(" Inline Security Verdicts:")
    for code, cnt in sorted(verdict_stats.items()):
        name = VERDICT_LABELS.get(code, f"CODE_{code}")
        pct = (cnt / len(packets)) * 100.0
        report.append(f"   - {name:<16}: {cnt:>8,} ({pct:5.1f}%)")
    report.append("=" * 62)
    print("\n" + "\n".join(report) + "\n")


if __name__ == "__main__":
    main()
