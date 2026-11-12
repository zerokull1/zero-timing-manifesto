# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust data-plane core and `x86_64` bare-metal architectural blueprint.**

> **Language:** **English** | [Русская версия (`README.ru.md`)](README.ru.md)  
> **Reproducible Hardware Logs:** Raw `lscpu`, `/proc/meminfo`, and execution telemetry are available in [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

The repository is structured into a Production Core Data-Plane Engine (featuring branchless `x86_64` ASM L7 DPI, zero-copy `AF_XDP`, active TCP shield, and Vulkan Compute GPU sideband offload) alongside Experimental R&D Firmware Blueprints (`uefi_stage0` and Ring -1 hypervisor stubs). Detailed performance benchmarks ranging from 0.53 cycles/packet (SMP matrix stress) to ~69 cycles (isolated L1 cache-line read) as well as full compilation and reproduction steps for the Linux XDP filter, C-ABI plugins, and UEFI bootloader are documented directly in this main showcase file.
