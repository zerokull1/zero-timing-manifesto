# Zero-Timing Manifesto (Русская документация)

![Status](https://shields.io)
![CI](https://github.com)
![Rust](https://shields.io)
![Arch](https://shields.io)
![License](https://shields.io)

**Детерминированное сверхнизколатентное ядро обработки пакетов на чистом `no_std` Rust и архитектурный эталон `x86_64` bare-metal.**

> **Язык:** [English (`README.md`)](README.md) | **Русский**  
> **Воспроизводимые аппаратные логи:** Сырой вывод `lscpu`, `/proc/meminfo` и телеметрия запуска доступны в [`docs/BENCHMARK_LOGS.md`](docs/BENCHMARK_LOGS.md).

Документация включает описание боевого Data-Plane ядра (безветвящийся L7 DPI, Zero-Copy `AF_XDP`, асинхронный GPU Offload через Vulkan Compute, модули C-ABI для Cisco DAQ и биржевых SBE/ITCH потоков), а также экспериментальные R&D компоненты (UEFI Stage 0 и каркас гипервизора). Полные инструкции по сборке всех модулей и таблицы тактовых замеров находятся в основном файле [`README.md`](README.md).
---

### Поддержать проект
Если желаете помочь развитию исследований и новых инструментов, вы можете отправить **TON** или **USDT (сеть TON)**:
```text
UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z
```
---

## 6. Корпоративные продукты и коммерческие пилоты (B2B)

Для промышленного внедрения, коммерческого лицензирования (без ограничений GPL-3.0) и запуска 14-дневного пилота (PoC) см. **[Руководство по корпоративным решениям](docs/ENTERPRISE_SOLUTIONS.md)**:

* **Zero-Shield (Телеком, хостинг и Anti-DDoS):** Фильтрация входящего трафика на линейной скорости через XDP, защита от тетеринга по TTL и C-ABI ускоритель для Snort/Suricata (`libzero_cisco_daq.so`).
* **Zero-Bridge (HFT и финтех):** Детерминированный `no_std` парсер биржевых протоколов (SBE/ITCH) без аллокаций с интерфейсом C-ABI (`libzero_hft_exchange.so`), поддержкой 2MB HugePages и аппаратных меток времени PTP.
