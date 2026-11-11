# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust core and x86_64 bare-metal architectural blueprint.**

Designed for high-frequency trading (HFT), inline Deep Packet Inspection (DPI), Web Application Firewalls (WAF), and rack-scale server infrastructure with hybrid CPU + GPU thermal offloading.

---

## ⚡ Core Architectural Pillars

* **Zero-Dependency `no_std` Execution:** Built without standard library or OS runtime overhead (`-nostartfiles`, `-nodefaultlibs`), using direct Linux `syscall` primitives for user-space telemetry.
* **Active Inline TCP Shield (L3/L4 Normalization):** Deterministic mitigation of stateful bypass anomalies (`0x00` Null-segments via `ACK` injection and `TTL` desynchronization normalization) paired with non-temporal `movnti` SIEM forensics dumps to NVMe DMA pages.
* **Hybrid CPU + GPU Offload (Thermal & TDP Optimization):** PCIe cold-boot enumeration (`class 0x01` NVMe, `class 0x02` NIC, `class 0x03` iGPU/dGPU `BAR0`/`BAR2`) offloads heavy Inter-Arrival Time (IAT) and Shannon entropy spectral analysis to GPU Compute queues via cache-bypassing DDR rings, keeping server CPU cores cool under 100G+ load.
* **Cache-Line Sterile Memory Layout:** Strict `#[repr(C, align(4096))]` per-core matrices (`128` cores) and 64-byte cache-line alignment paired with hardware prefetching (`prefetcht0`/`prefetchw`).
* **Direct x86_64 Hardware Control:** Low-level manipulation of control registers (`CR0`, `CR3`, `CR4`), PCIe `0xCF8`/`0xCFC` enumeration, GDT transitions, and custom `#PF` (`iretq`) handlers.

---

## 📊 Hardware Cycle Benchmarks (`rdtscp` + `lfence`)

Measured on warmed TLB/L1 pages (`taskset -c 0`) in a `no_std` Linux User-Space simulation:

| Execution Path | Low-Level Operations | Latency (CPU Cycles) | Approx. Time (@ 3.5 GHz) |
| :--- | :--- | :---: | :---: |
| **Bare-Metal Ring 0 Shield (UEFI Boot)** | `rdtsc` + `lfence` + `TTL`/`ACK` Norm + `movnti` + `sfence` (QEMU/OVMF) | **27 cycles** | ~7.7 ns |
| **Phase 1 Clean Fast-Path + GPU IAT** | `read_volatile` + `movnti` + `prefetchw` + `sfence` + GPU Doorbell | **57 cycles** | ~16.3 ns |
| **Phase 2/3 Bypass Blocked (Active Shield)** | `TTL` Norm + `ACK` Inject + `movnti` (NVMe SIEM + GPU IAT) + Doorbells | **66 cycles** | ~18.9 ns |
| **L1 Cache-Line Read (Baseline)** | `#[repr(align(64))]` + `prefetcht0` | **69 cycles** | ~19.7 ns |

### 🔬 Spectral IAT Entropy Benchmarks (Vulkan Compute GPU Offload)

Measured on NVIDIA GeForce GTX 1050 (`shaderInt64` + 16-bin `shared` memory histogram) reading directly from `/dev/shm/zero_shield_ring`:

| Traffic Profile | Threshold Jitter Alerts | Shannon IAT Entropy ($H$) | GPU Shield Verdict |
| :--- | :---: | :---: | :--- |
| **Deterministic Flow (Phase 1)** | `0` (or isolated spikes) | **0.1165 bits** | `DETERMINISTIC FLOW` |
| **Dynamic Padding / Hysteria2** | `0` (evades threshold) | **3.9566 bits** | `HIGH ENTROPY (Suspected)` |

```bash
make -C gpu_offload && ./gpu_offload/vk_iat_bridge
```

---

## 📂 Repository Structure

```text
├── .cargo/              # Compiler flags and bare-metal target settings
├── src/
│   ├── main.rs          # Entry point, direct Linux syscalls, and benchmark runner
│   ├── core_engine.rs   # Per-core matrix, PCIe GPU/NVMe/NIC scan, Active Shield & DMA offload
│   └── tsc.rs           # Serialized hardware cycle counter (rdtsc / rdtscp + lfence)
├── docs/                # Architectural notes, register maps, and deployment guides
├── gpu_offload/         # Vulkan Compute SPIR-V kernel & Zero-Copy DDR bridge (/dev/shm)
├── Cargo.toml           # Package manifest (panic = "abort", LTO enabled)
├── LICENSE              # GNU General Public License v3.0 (GPL-3.0)
└── README.md            # Project overview, benchmarks, and licensing terms
```

---

## 🛠️ Building & Running Benchmarks

```bash
git clone https://github.com/zerokull1/zero-timing-manifesto.git
cd zero-timing-manifesto
cargo build --release
taskset -c 0 ./target/release/zero_project
```

> **Note:** Bare-metal Ring 0 routines (`enumerate_pcie_bus_cold_boot`, `CR0`/`CR4` writes, `cli`, PCIe `0xCF8`/`0xCFC` I/O) require kernel-space or UEFI execution and will trigger a General Protection Fault (`#GP`) in standard Linux User Space.

---

## 🔗 Related Research

* **[Stateful Inline Bypass Manifesto](https://github.com):** Theoretical specification of three-phase L3/L4/L7 desynchronization and the symmetric Active Shield architecture implemented in `core_engine.rs`.

---

## 💼 Dual-Licensing & Commercial Integration Support

* **Open Source License (GPL-3.0):** For academic and non-commercial use (modifications require open-sourcing under GPL-3.0).
* **Commercial License:** Required for enterprise, HFT, or closed-source integration. Contact: **1zerokull1@gmail.com** (`[COMMERCIAL INQUIRY] Company Name - Core Integration`).

*(C) 2026 zerokull1. All Rights Reserved.*
