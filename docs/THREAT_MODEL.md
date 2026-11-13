# Hardware Threat Model & Silicon Boundaries

| # | Attack Surface | Root Cause | Software & Hardware Mitigation in Zero-Timing |
| :--- | :--- | :--- | :--- |
| **1** | **Driver Dead-End** | Proprietary GPUs lack open register specs | Split-plane: open Intel `BAR0 MMIO` in `Ring 0`; proprietary GPU isolated via non-temporal `ZERORING` |
| **2** | **DDR Cold Boot** | Cryogenic cooling preserves DDR charge after power-off | **CPU Register-Bound Keys (`YMM15` TRESOR-mode)** inside CPU silicon + server **Intel TME / AMD SME** |
| **3** | **Sub-Ring 0 (`ME/SMM`)** | `Ring -2` SMM & ME run below OS/hypervisor | `SMRAM` lock (`D_LCK`) at `UEFI Stage 0` + `me_cleaner` / `HAP` bit on SPI flash |
| **4** | **No OS Guards** | Unikernels lack `KASLR` and `W^X` | Hardware **`NX / XD`** bits in `PML4` page tables, zero heap (`no alloc`), and **Intel VT-d `IOMMU`** |
| **5** | **USB / BadUSB** | Spoofed HID firmware or `xHCI` bus sniffing | Encrypted USB blob + keyboard PIN decrypted only in `YMM15` + `bInterfaceClass == 0x08` check |
