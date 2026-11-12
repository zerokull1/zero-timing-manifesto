# Zero-Timing Manifesto

![Status](https://shields.io)
![CI](https://github.com)
![Rust](https://shields.io)
![Arch](https://shields.io)
![License](https://shields.io)

**Deterministic, ultra-low-latency `no_std` Rust (2024 Edition) data-plane core and `x86_64` bare-metal architectural blueprint.**

> **Language:** **English** | [Русская версия (`README.ru.md`)](README.ru.md)  
> **Hardware Logs:** Raw `lscpu`, `/proc/meminfo`, and execution telemetry are archived in [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

## Data-Plane Packet Flow Architecture

```mermaid
flowchart LR
    NIC["NIC / Kernel Ingress<br/>(XDP / Zero-Copy AF_XDP)"] --> CPU["Isolated CPU Core 0<br/>Branchless x86_64 ASM & SWAR<br/>(27–36 cycles/pkt)"]
    CPU --> ACTION{"Inline Verdict"}
    ACTION -- "Pass / Forward" --> WIRE["TX Ring / HFT Bridge<br/>(SBE / ITCH / DPDK)"]
    ACTION -- "Drop (Malicious)" --> DROP["Hardware / XDP Drop<br/>(Zero Allocation)"]
    CPU -. "Non-Temporal Store<br/>(vmovntdq)" .-> RING["ZERORING Lock-Free Buffer<br/>(2MB HugePages)"]
    RING -. "Async Sideband" .-> GPU["Vulkan Compute Sideband<br/>(Shannon IAT Entropy)"]
    RING -. "Zero-Alloc Read" .-> TUI["TUI Radar & Watchdog"]
```

## Active Security, Deception & Mutation Pipeline

```mermaid
flowchart TD
    IN["Incoming Traffic / L7 Payload"] --> GATE["1. Constant-Time Hash Gate & L7 Shield<br/>(Zero-Timing Side-Channel Resistance)"]
    
    GATE -- "Verified Clean Flow" --> ENC["Encrypted / Isolated Memory Ring<br/>(Zero-Copy Protected Handoff)"]
    GATE -- "Anomaly / Probe Detected" --> TRAP{"2. Threat & Entropy Classifier<br/>(CPU SWAR + GPU Shannon IAT)"}
    
    TRAP -- "Scanner / Recon Bot" --> HONEY["Deception Trap / Tarpit Isolation<br/>(Synthetic Decoy Response & Sinkhole)"]
    TRAP -- "DPI Evasion / Polymorphic Probe" --> MUT["Dynamic State Mutation (MTD)<br/>(Rolling Hash Seeds & Signature Rotation)"]
    TRAP -- "Critical Flood / Exploit" --> DROP["Hardware XDP Drop + DDR Flight Recorder<br/>(Instant Mitigation & Forensic Dump)"]
```

## 1. Architectural Separation: Inline Fast-Path vs. Sideband & R&D

* **Inline CPU Fast-Path (`27–36 cycles/pkt`):** Branchless `x86_64` ASM L7 DPI (`cmov`), zero-copy `AF_XDP`, and `XDP` kernel ingress filtering make pass/drop decisions in nanoseconds with zero heap allocations.
* **Asynchronous GPU Sideband (`Out-of-Band`):** Vulkan Compute reads non-temporal `ZERORING` buffers (`vmovntdq`) in the background for Shannon IAT entropy analysis without adding latency to the packet path.
* **Experimental R&D Blueprints:** `uefi_stage0` and `thin_hypervisor.rs` provide pre-OS boot attestation and `VT-x`/`AMD-V` Ring -1 stubs.

## 2. Hardware Cycle Benchmarks (`rdtscp + lfence`)

### Reference Testbed & Call for Hardware Benchmarks

All baseline numbers below were measured on a standard desktop workstation (**Intel Core i5-4590 Haswell, 3.30 GHz, AVX2 only / no AVX-512** + **NVIDIA GTX 1050 Pascal** for Vulkan Compute sideband):

* **Desktop Hardware Baseline:** XDP/AF_XDP benchmarks were executed without server-grade hardware `Intel DDIO` or native zero-copy server NIC drivers — meaning modern `Xeon Scalable` or `AMD EPYC` servers will achieve even lower cycle counts.
* **Community Call for `XDP_DRV` Tests:** Contributions from engineers with server NICs (**Intel X710 / E810**, **Mellanox ConnectX-5/6**) running native `XDP_DRV` zero-copy benchmarks via GitHub Issues or PRs are very welcome!

| Execution Layer / Component | Measured Latency | Measurement Methodology & Scope |
| :--- | :--- | :--- |
| **SMP 4-Core Matrix (`10M pkts`)** | **~0.5–0.6 ns/pkt** | Amortized aggregate throughput across 4 isolated cores (`align(4096)`, zero false-sharing) |
| **Bare-Metal Ring 0 Shield (`QEMU/OVMF`)** | **~27 cycles** | Amortized per-frame cost inside a warm packet batch (serialization outside inner loop) |
| **Branchless ASM L7 DPI (`TLS/HTTP/QUIC`)** | **30–36 cycles** | Warm L1 instruction cache batch inspection (`cmov` / SWAR, zero branches) |
| **Isolated L1 Cache-Line Read** | **~69 cycles** | Single cold call including full pipeline serialization (`rdtscp + lfence` overhead) |
| **GPU Sideband IAT Entropy (`Vulkan`)** | **48–66 CPU cycles** | Host CPU dispatch cost only (non-temporal ring write; GPU compute runs asynchronously) |
| **Native C-ABI Shared Lib (`10M pkts`)** | **~~12 ns/pkt** | Direct `gcc -O3` call into `libzero_cisco_daq.so` on 1 core (**~80 Mpps**, zero Python overhead) |
| **C-ABI Replay via Python FFI (`100k pkts`)** | **~820 ns (p50)** | End-to-end `libzero_cisco_daq.so` call overhead incl. Python `ctypes` FFI (`~0.83 Mpps`) |

## 3. Module Readiness Matrix

| Module / Directory | Status | Role & Technical Scope |
| :--- | :--- | :--- |
| `src/l7_shield.rs`, `src/ttl_guard.rs`, `src/af_xdp_engine.rs` | **Beta / Verified** | Branchless L3/L4/L7 SWAR inspection, self-learning `TTL` EMA guard & IPv4 whitelist |
| `xdp_shield/`, `cisco_daq_plugin/`, `hft_exchange_bridge/` | **Beta / Verified** | Linux kernel XDP hook & C-ABI `.so` plugins for Snort 3 / DPDK / SBE / ITCH |
| `include/zero_timing.h`, `integrations/python/`, `integrations/go/` | **Beta / Verified** | Zero-dependency C/C++, Python (`ctypes`), Go (`mmap`) SDKs & `systemd` XDP unit |
| `src/numa_hugepages.rs`, `src/pcie_ddio_ptp.rs` | **Beta / Verified** | Raw syscall `2MB HugePages`, `NUMA MPOL_BIND`, Intel DDIO & PTP PHC reader |
| `ring_reader/zero_tui_radar.rs`, `src/runtime_guard.rs` | **Beta / Verified** | Zero-allocation live telemetry TUI radar, Watchdog & DDR Flight Recorder |
| `uefi_stage0/`, `src/thin_hypervisor.rs` | **R&D Blueprint** | Bare-metal UEFI Stage 0 pre-OS loader & `VT-x` / `AMD-V` Ring -1 skeleton |

## 4. Building & Reproducing Benchmarks

```bash
# Run full end-to-end verification & benchmark suite
./demo_run.sh

# Build release core binary & pin to isolated CPU core 0
cargo build --release && taskset -c 0 ./target/release/zero_project

# Build C-ABI shared libraries (Cisco DAQ & HFT Exchange Bridge)
rustc --crate-type cdylib -C panic=abort -O cisco_daq_plugin/lib.rs -o cisco_daq_plugin/libzero_cisco_daq.so
rustc --crate-type cdylib -C panic=abort -O hft_exchange_bridge/lib.rs -o hft_exchange_bridge/libzero_hft_exchange.so

# Run offline PCAP / synthetic threat replay benchmark (no NIC/root required)
python3 tools/pcap_bench.py --count 100000
# Or replay a real .pcap capture file:
# python3 tools/pcap_bench.py --pcap capture.pcap
```

## 5. Dual Licensing & Commercial Support

* **Open-Source (`GPL-3.0`):** Free for research, auditing, and open-source deployments under [`LICENSE`](LICENSE).
* **Commercial Integration:** Proprietary integration without `GPL-3.0` copyleft obligations is available via [GitHub Issues](https://github.com).
---

### Support the Project
If you would like to support further research and open-source tools, you can send **TON** or **USDT (TON network)**:
```text
UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z
```