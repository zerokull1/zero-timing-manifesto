# Hardware Threat Model & Silicon Boundaries

An honest engineering audit of physical, firmware, and bus-level attack vectors against bare-metal `Ring 0` Unikernels and `no_std` memory-pinned vaults—along with concrete hardware mitigations.

| # | Attack Surface / Limit | Root Cause | Architectural Mitigation in Zero-Timing |
| :--- | :--- | :--- | :--- |
| **1** | **Driver Dead-End** | Proprietary GPUs/NICs lack open register specs for `Ring 0` | Strict split-plane: open Intel `BAR0 MMIO` (`e1000`/`ixgbe`) in `Ring 0` fast-path; proprietary GPU (`Vulkan`) isolated in user-space via non-temporal `ZERORING` |
| **2** | **DDR Cold Boot Attack** | Cryogenic cooling preserves DDR capacitor charge for seconds/minutes after power loss | Server **Intel TME / AMD SME** memory encryption; on desktop CPUs, **CPU Register-Bound Keys** (`YMM0–YMM15` / `DR0–DR3` TRESOR-style) + UEFI `MemoryOverwriteRequestControl` |
| **3** | **Sub-Ring 0 (`ME / PSP / SMM`)** | Management Engine & `Ring -2` SMM operate below the OS/hypervisor with full RAM access | **Intel ME HAP / `me_cleaner`** neutralization, `SMRAM` lock (`D_LCK`) at `UEFI Stage 0`, and disabling Out-of-Band NIC sharing |
| **4** | **Missing OS Protections** | Unikernels lack `KASLR`, `W^X`, and process isolation | Hardware **`NX / XD` (No-Execute)** bit in `PML4` page tables for stack/DMA rings, zero dynamic heap (`no alloc`), and **Intel VT-d `IOMMU`** DMA isolation |
| **5** | **USB Bus & BadUSB** | Spoofed HID firmware on flash drives or `xHCI` bus sniffing | **2FA Split Secret** (encrypted blob on USB + short keyboard PIN decrypted only inside CPU registers) + strict `bInterfaceClass == 0x08` (Mass Storage only) enforcement |
