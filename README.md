# Zero-Timing Manifesto

**Deterministic, ultra-low-latency `no_std` Rust data-plane core and `x86_64` bare-metal architectural blueprint.**

Подробное описание архитектуры, разделение на боевое ядро (Data-Plane) и исследовательские R&D модули, а также полная таблица замеров с описанием методик для каждой строки доступны в исходном репозитории.

> 📊 **Raw Hardware Logs:** Воспроизводимые логи с тестовой станции доступны в [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

## 🛠 Building & Reproducing Benchmarks

* Запуск комплексного пайплайна: `./demo_run.sh`
* Сборка и запуск базовых бенчмарков: `cargo build --release && taskset -c 0 ./target/release/zero_project`
* Инструкции по остальным компонентам (`gpu_offload`, `xdp_shield`, `uefi_stage0`) см. в репозитории.

