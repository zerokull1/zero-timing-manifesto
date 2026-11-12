# Hardware & Benchmark Execution Logs

Raw reproducible telemetry captured directly on the development workstation.

## 1. System & CPU Topology
```text
Linux zer0 7.2.14-zen1-1-zen #1 ZEN SMP PREEMPT_DYNAMIC Fri, 30 Oct 2026 14:32:44 +0000 x86_64 GNU/Linux
CPU(s):                                  4
On-line CPU(s) list:                     0-3
Имя модели:                              Intel(R) Core(TM) i5-4590 CPU @ 3.30GHz
Thread(s) per core:                      1
CPU(s) scaling MHz:                      89%
CPU max MHz:                             3700,0000
CPU min MHz:                             800,0000
NUMA node0 CPU(s):                       0-3
AnonHugePages:   1488896 kB
ShmemHugePages:        0 kB
FileHugePages:   1748992 kB
HugePages_Total:      32
HugePages_Free:       32
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:           65536 kB
```

## 2. Full End-to-End Pipeline Output (`./demo_run.sh`)
```text
=================================================================
  ZERO-TIMING MANIFESTO — ONE-CLICK FULL-STACK VERIFICATION
=================================================================
[1/5] Building no_std Rust Core (x86_64)...
[2/5] Building Vendor & HFT C-ABI Shared Libraries (.so)...
[3/5] Running Core Hardware Cycle Benchmarks (taskset -c 0)...
[Rack-Scale Shield + GPU IAT Offload]
279 CPU cycles
33 CPU cycles
0x030x10  4. Rack CPU Worker (No-GPU Mode): Jitter=4 | Entropy=0.07 bits
  5. SMP Matrix Stress (4 Cores, Zero False-Sharing): 10000000 pkts in 23652576 cycles (~0.6 ns/pkt aggregate)
  6. Branchless x86_64 ASM L7 DPI (TLS + HTTP): 219 cycles | Verdict Mask: 0x01  7. AF_XDP Zero-Copy UMEM Subsystem: 1
[4/5] Verifying Cross-Platform ZERORING Telemetry Reader...
[ZERORING] Target mapped (/dev/shm/zero_shield_ring), magic=0x00001EDF54BD17D1 (awaiting Stage 0 / Active Shield init)
[5/5] Checking Artifacts...
-rwxr-xr-x 1 zero zero 5,5K ноя 12 09:46 cisco_daq_plugin/libzero_cisco_daq.so
-rwxr-xr-x 1 zero zero 5,2K ноя 12 09:46 hft_exchange_bridge/libzero_hft_exchange.so
-rwxr-xr-x 1 zero zero 4,5M ноя 12 09:46 ring_reader/zeroring_reader
-rwxr-xr-x 2 zero zero  15K ноя 12 09:00 target/release/zero_project
=================================================================
  ALL MODULES VERIFIED SUCCESSFULLY!
=================================================================
```

## v1.1.0-beta C-ABI PCAP Replay Benchmark (2026-11-12 16:50 UTC)
```text
[*] Генерация синтетического микса (TLS 1.3 / HTTP / Malformed Flood): 100000 пакетов...

==============================================================
 ZERO-TIMING C-ABI REPLAY REPORT (100,000 packets)
==============================================================
 Total Wall Time   : 0.1175 s (0.85 Mpps incl. Python FFI)
 Latency p50       :    811 ns
 Latency p95       :    895 ns
 Latency p99       :   1972 ns
 Latency p99.9     :  12538 ns
--------------------------------------------------------------
 Inline Security Verdicts:
   - DROP            :  100,000 (100.0%)
==============================================================
```
