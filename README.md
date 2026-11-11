# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust core and x86_64 bare-metal architectural blueprint.**

Designed for high-frequency trading (HFT), inline Deep Packet Inspection (DPI), Web Application Firewalls (WAF), and server-rack kernel-bypass infrastructure.

---

## ⚡ Core Architectural Pillars

* **Zero-Dependency `no_std` Execution:** Built without standard library or OS runtime overhead (`-nostartfiles`, `-nodefaultlibs`).
* **DDR Memory Traps & NVMe DMA Offload:** 4-byte signature filtering (`0xDEADBEEF`) directly in DDR with non-temporal `movnti` writes to NVMe DMA pages, bypassing CPU caches.
* **Cache-Line Sterile Memory Layout:** Strict `#[repr(C, align(4096))]` per-core matrices and 64-byte cache-line alignment paired with hardware prefetching (`prefetcht0`/`prefetchw`).
* **Direct x86_64 Hardware Control:** Low-level manipulation of control registers (`CR0`, `CR3`, `CR4`), PCIe BAR0 enumeration, GDT transitions, and custom `#PF` (`iretq`) handlers.
* **SIMD & Vectorized Fast-Paths:** Utilizing 256-bit AVX registers for zero-copy packet inspection.

---

## 📊 Hardware Cycle Benchmarks (`rdtscp` + `lfence`)

Measured on warmed TLB/L1 pages in a `no_std` Linux User-Space simulation:

| Execution Path | Low-Level Operations | Latency (CPU Cycles) | Approx. Time (@ 3.5 GHz) |
| :--- | :--- | :---: | :---: |
| **L1 Cache-Line Read** | `#[repr(align(64))]` + `prefetcht0` | **69 cycles** | ~19.7 ns |
| **DDR Trap + NVMe Offload** | `cmp 0xDEADBEEF` + `movnti` + `sfence` + Doorbell | **75 cycles** | ~21.4 ns |
| **Clean Packet Fast-Path** | `write_volatile` + `clflush` + `sfence` + Doorbell | **93 cycles** | ~26.5 ns |

---

## 📂 Repository Structure

```text
├── .cargo/              # Compiler flags and bare-metal target settings
├── src/
│   ├── main.rs          # Entry point, direct Linux syscalls, and benchmark runner
│   ├── core_engine.rs   # Per-core matrix, PCIe BAR0, DDR trap, and NVMe DMA offload
│   └── tsc.rs           # Serialized hardware cycle counter (rdtsc / rdtscp + lfence)
├── docs/                # Architectural notes, register maps, and deployment guides
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
./target/release/zero_project
```

> **Note:** Bare-metal Ring 0 routines (`run_bare_metal_loop`, `CR0`/`CR4` writes, `cli`, PCIe `0xCF8`/`0xCFC` I/O) require kernel-space or UEFI execution and will trigger a General Protection Fault (`#GP`) in standard Linux User Space.

---

## 💼 Dual-Licensing & Commercial Integration Support

* **Open Source License (GPL-3.0):** For academic and non-commercial use (modifications require open-sourcing under GPL-3.0).
* **Commercial License:** Required for enterprise, HFT, or closed-source integration. Contact: **1zerokull1@gmail.com** (`[COMMERCIAL INQUIRY] Company Name - Core Integration`).

*(C) 2026 zerokull1. All Rights Reserved.*
