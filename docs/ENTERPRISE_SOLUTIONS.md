# Enterprise Solutions & Commercial Deployment Guide

**Zero-Timing Core** delivers deterministic, zero-allocation packet inspection and market-data parsing on commodity x86_64 hardware without heavy kernel-bypass frameworks (DPDK) or proprietary ASICs.

---

## 1. Zero-Shield: Telecom, Hosting & Anti-DDoS Edition

Designed for ISPs, cloud providers, and enterprise edge networks facing L7 floods, reconnaissance probes, and unauthorized tethering.

### Key Capabilities
* **Line-Rate XDP Ingress Filtering:** Drops volumetric floods and unauthorized tethering (TTL 65/129 anomalies) directly inside the NIC driver before `sk_buff` allocation.
* **Branchless L7 DPI (`libzero_cisco_daq.so`):** Drop-in C-ABI replacement/accelerator for Snort 3 and Suricata. Inspects HTTP/TLS/QUIC headers in **30–36 CPU cycles** with zero conditional branches.
* **Active Deception & Tarpit:** Automatically routes polymorphic scanners into synthetic decoy sinkholes (`DECEPTION_TRAP`) while dropping critical exploits (`DROP`).
* **Asynchronous GPU Sideband:** Offloads Shannon IAT entropy calculations via Vulkan Compute without adding latency to the inline packet path.

### Verified Replay Benchmark (1,000,000 Packets)
* **Throughput (incl. Python ctypes FFI):** `0.90 Mpps` (1.11s total wall time on 1 core)
* **Native C-ABI Throughput:** `~80 Mpps` (~12 ns/pkt)
* **Inline Classification Split:** `33.4% DROP` | `66.6% DECEPTION_TRAP`

---

## 2. Zero-Bridge: HFT & Low-Latency Fintech Edition

Built for proprietary trading firms, market makers, and crypto exchanges requiring deterministic tail latency (p99/p99.9).

### Key Capabilities
* **Zero-Allocation `no_std` Core:** 100% standalone static execution with zero heap allocations, zero garbage collection, and zero OS context switches.
* **Deterministic SBE / ITCH Parsing (`libzero_hft_exchange.so`):** Constant-time `cmov` and SWAR execution eliminates branch misprediction penalties.
* **Hardware-Sympathetic Memory:** Native 2MB HugePages (`ZERORING`), NUMA pinning (`MPOL_BIND`), Intel DDIO cache awareness, and direct PTP Hardware Clock (`/dev/ptp0`) timestamping.

---

## 3. Deployment Topologies & SLA Safety

1. **Bump-in-the-Wire (Inline XDP):** Deployed on Linux edge routers (`xdpdrv` native mode) for sub-microsecond DDoS mitigation.
2. **IDS/IPS Drop-In Accelerator:** Linked via C-ABI (`include/zero_timing.h`) into existing Suricata/Snort or C++ trading engines.
3. **Fail-Open Guarantee:** Engineered with hardware/driver bypass safety — if the user-space watchdog or daemon stops, traffic seamlessly continues flowing without dropping legitimate customer sessions.

---

## 4. Commercial Licensing & 14-Day Pilot (PoC)

While the research core is available under **GPL-3.0**, enterprise customers can obtain a **Commercial Proprietary License** (removing copyleft obligations) along with dedicated engineering support.

* **Free 14-Day PoC:** Test Zero-Shield or Zero-Bridge on a SPAN port (mirrored traffic) or replay your own `.pcap` captures.
* **Contact & Inquiries:** Open a ticket via GitHub Issues or request a private evaluation package.

---

## 5. Runtime Control Plane (Zero-Downtime Rule Updates)

Using `xdp_shield/zero_dynamic_shield.c` and `src/bpf_control.rs` (raw `SYS_bpf` syscalls), operators can modify filtering rules at runtime without reloading XDP hooks or dropping active connections:

```bash
# Compile dynamic XDP module with BTF metadata
clang -O2 -g -target bpf -c xdp_shield/zero_dynamic_shield.c -o xdp_shield/zero_dynamic_shield.o

# Hot-add trusted IPv4 (e.g., 10.99.0.2) to O(1) whitelist map
sudo bpftool map update name whitelist_v4 key hex 0a 63 00 02 value hex 01

# Instant Fail-Open switch (mode=0) or Enforce mode (mode=2)
sudo bpftool map update name config_map key hex 00 00 00 00 value hex 02 00 00 00  01 00 00 00  01 00 00 00

# Read lock-free per-CPU packet counters
sudo bpftool map dump name stats_map
```
