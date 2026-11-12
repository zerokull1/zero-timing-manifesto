# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust data-plane core and `x86_64` bare-metal architectural blueprint.**

> **Language:** **English** | [Русская версия (`README.ru.md`)](README.ru.md)  
> **Hardware Logs:** Raw `lscpu`, `/proc/meminfo`, and execution telemetry are archived in [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

## 1. Architectural Separation: Inline Fast-Path vs. Sideband & R&D

* **Inline CPU Fast-Path (`27–36 cycles/pkt`):** Branchless `x86_64` ASM L7 DPI (`cmov`), zero-copy `AF_XDP`, and `XDP` kernel ingress filtering make pass/drop decisions in nanoseconds with zero heap allocations.
* **Asynchronous GPU Sideband (`Out-of-Band`):** Vulkan Compute reads non-temporal `ZERORING` buffers (`vmovntdq`) in the background for Shannon IAT entropy analysis without adding latency to the packet path.
* **Experimental R&D Blueprints:** `uefi_stage0` and `thin_hypervisor.rs` provide pre-OS boot attestation and `VT-x`/`AMD-V` Ring -1 stubs.

## 2. Hardware Cycle Benchmarks (`rdtscp + lfence`)

| Execution Layer / Component | Measured Latency | Measurement Methodology & Scope |
| :--- | :--- | :--- |
| **SMP 4-Core Matrix (`10M pkts`)** | **~0.5–0.6 ns/pkt** | Amortized aggregate throughput across 4 isolated cores (`align(4096)`, zero false-sharing) |
| **Bare-Metal Ring 0 Shield (`QEMU/OVMF`)** | **~27 cycles** | Amortized per-frame cost inside a warm packet batch (serialization outside inner loop) |
| **Branchless ASM L7 DPI (`TLS/HTTP/QUIC`)** | **30–36 cycles** | Warm L1 instruction cache batch inspection (`cmov` / SWAR, zero branches) |
| **Isolated L1 Cache-Line Read** | **~69 cycles** | Single cold call including full pipeline serialization (`rdtscp + lfence` overhead) |
| **GPU Sideband IAT Entropy (`Vulkan`)** | **48–66 CPU cycles** | Host CPU dispatch cost only (non-temporal ring write; GPU compute runs asynchronously) |

## 3. Module Readiness Matrix

| Module / Directory | Status | Role & Technical Scope |
| :--- | :--- | :--- |
| `src/l7_shield.rs`, `src/af_xdp_engine.rs` | **Production Ready** | Branchless L3/L4/L7 SWAR inspection & zero-copy `AF_XDP` UMEM engine |
| `xdp_shield/`, `cisco_daq_plugin/`, `hft_exchange_bridge/` | **Production Ready** | Linux kernel XDP hook & C-ABI `.so` plugins for Snort 3 / DPDK / SBE / ITCH |
| `src/numa_hugepages.rs`, `src/pcie_ddio_ptp.rs` | **Production Ready** | Raw syscall `2MB HugePages`, `NUMA MPOL_BIND`, Intel DDIO & PTP PHC reader |
| `ring_reader/zero_tui_radar.rs`, `src/runtime_guard.rs` | **Production Ready** | Zero-allocation live telemetry TUI radar, Watchdog & DDR Flight Recorder |
| `uefi_stage0/`, `src/thin_hypervisor.rs` | **R&D Blueprint** | Bare-metal UEFI Stage 0 pre-OS loader & `VT-x` / `AMD-V` Ring -1 skeleton |

## 4. Building & Reproducing Benchmarks

```bash
# Run full end-to-end verification & benchmark suite
./demo_run.sh

# Build release core binary & pin to isolated CPU core 0
cargo build --release && taskset -c 0 ./target/release/zero_project

# Build C-ABI shared libraries (Cisco DAQ & HFT Exchange Bridge)
rustc --crate-type cdylib -O cisco_daq_plugin/src/lib.rs -o cisco_daq_plugin/libzero_cisco_daq.so
rustc --crate-type cdylib -O hft_exchange_bridge/src/lib.rs -o hft_exchange_bridge/libzero_hft_exchange.so
```

## 5. Dual Licensing & Commercial Support

* **Open-Source (`GPL-3.0`):** Free for research, auditing, and open-source deployments under [`LICENSE`](LICENSE).
* **Commercial Integration:** Proprietary integration without `GPL-3.0` copyleft obligations is available via [GitHub Issues](https://github.com).
