---
name: Feature / Protocol Integration Request
about: Suggest a new L7 protocol parser, NIC driver hook, or C-ABI integration
title: "[FEAT] "
labels: enhancement
---

### Target Use Case & Protocol
- **Domain:** (e.g., Inline DPI/WAF, eBPF/XDP Gateway, HFT SBE/ITCH, Telemetry)
- **Target Interface / Protocol:** (e.g., WireGuard/QUIC parsing, DPDK rte_mbuf wrapper, ARM64 NEON port)

### Performance & Hardware Constraints
- **Target Latency Budget:** (e.g., < 50 cycles/pkt, < 1 µs)
- **CPU / NIC Architecture:** (e.g., x86_64 AVX2, Mellanox ConnectX-6, Intel E810)

### Additional Context
Describe what you would like to integrate or improve.
