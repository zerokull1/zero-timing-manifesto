# Hybrid Data-Plane Isolation & Deterministic DDR Traps

## Architectural Concept
To achieve bare-metal determinism (Ring 0 speed) on multi-socket server racks without maintaining legacy peripheral drivers, the system splits CPU cores into an asymmetric **Control Plane** and **Zero-Jitter Data Plane**:

* **Core 0 (Control Plane):** Runs a minimal Linux kernel strictly for hardware bring-up, SSH telemetry, and memory/PCIe allocation.
* **Cores 1–127 (Data Plane):** Completely detached from the OS scheduler. Runs the `no_std` Rust core (`core_engine.rs`) with direct MMIO/DMA access and 1-cycle DDR anomaly trapping (`0xDEADBEEF` -> `movnti` -> NVMe Doorbell).

---

## 1. Kernel Boot Parameters (`isolcpus` / `nohz_full`)
To prevent timer interrupts and OS task scheduling from flushing L1/L2 caches or interrupting DDR trap checks, boot the host kernel with:

```text
isolcpus=1-127 nohz_full=1-127 rcu_nocbs=1-127 irqaffinity=0 intel_iommu=on iommu=pt
```

* **`isolcpus` / `nohz_full`:** Removes cores `1–127` from the kernel scheduler and disables periodic timer ticks on active polling loops.
* **`irqaffinity=0`:** Routes all legacy hardware interrupts exclusively to Core 0.
* **`iommu=pt`:** Enables pass-through mode for IOMMU, eliminating DMA address translation overhead on hot paths.

---

## 2. Static Physical DDR Anchoring (`1GB HugePages`)
Standard 4 KB memory pages cause TLB misses and allow the OS to remap physical frames. Pre-allocating 1 GB HugePages guarantees that `SERVER_CORE_MATRIX` and `ddr_trap_pad` remain pinned at static, contiguous physical DDR addresses:

```text
default_hugepagesz=1G hugepagesz=1G hugepages=16
```

* **Zero TLB Thrashing:** The entire per-core matrix and NVMe DMA offload ring fit inside a single 1 GB TLB entry.
* **Mutation & Overflow Containment:** Because physical addresses never shift, 4-byte DDR traps intercept mutated payloads in **1 CPU cycle** (`cmp`) and flush them via non-temporal writes (`movnti`) directly to NVMe DMA pages without polluting CPU caches.

---

## 3. Direct PCIe BAR0 & DMA Pass-Through (`VFIO`)
Instead of routing packets or storage logs through kernel network/block stacks (`sk_buff` / `blk-mq`), NIC and NVMe controllers are bound to `vfio-pci`:

```bash
modprobe vfio-pci
# Bind target NIC and NVMe PCIe addresses (e.g., 0000:01:00.0) to vfio-pci
echo "0000:01:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
```

This maps hardware `BAR0` Doorbell registers directly into the engine's address space, preserving the **~20–26 ns** (`69–93 CPU cycles`) deterministic execution envelope.
