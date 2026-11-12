# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust data-plane core and `x86_64` bare-metal architectural blueprint.**

> **Language:** **English** | [Русская версия (`README.ru.md`)](README.ru.md)  
> **Reproducible Hardware Logs:** Raw `lscpu`, `/proc/meminfo`, and execution telemetry are available in [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

The repository is structured into a Production Core Data-Plane Engine (featuring branchless `x86_64` ASM L7 DPI, zero-copy `AF_XDP`, active TCP shield, and Vulkan Compute GPU sideband offload) alongside Experimental R&D Firmware Blueprints (`uefi_stage0` and Ring -1 hypervisor stubs). Detailed performance benchmarks ranging from 0.53 cycles/packet (SMP matrix stress) to ~69 cycles (isolated L1 cache-line read) as well as full compilation and reproduction steps for the Linux XDP filter, C-ABI plugins, and UEFI bootloader are documented directly in this main showcase file.

---

## 📊 Hardware Cycle Benchmarks & Module Matrix

Полные таблицы аппаратных замеров тактов (`rdtscp + lfence`), метрик асинхронного GPU-анализатора энтропии (Vulkan Compute IAT Entropy) и матрицу зрелости модулей (включая `src/l7_shield.rs`, `cisco_daq_plugin/`, `uefi_stage0/` и др.) вы можете найти непосредственно в структуре репозитория и файлах исходного кода [https://github.com].

---

## 🛠 Building & Reproducing Benchmarks

Инструкции по сборке, команды верификации (`./demo_run.sh`, `cargo build --release`), а также условия двойного лицензирования (`GPL-3.0` и коммерческие лицензии) доступны в репозитории проекта.
