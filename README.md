# ZERO-TIMING BARE-METAL MANIFESTO (STAGE 0 + ZERO-CPU IDLE)

Experimental Proof-of-Concept (PoC) hardware-assisted defense mechanism against Layer 3/4 TCP TTL Desynchronization attacks (Phase 2 & Phase 3 stateful table bypasses).

## Architecture Overview

1. **Stage 0 UEFI Explorer**: A sterile `no_std` Rust binary (under 3 KB) executing via custom initialization vectors. It polls the hardware configuration space (`CPUID` registers and PCIe I/O ports `0xCF8`/0xCFC) to dynamic patch assembly branches at early boot, avoiding runtime branch mispredictions and software jitter.
2. **Zero-CPU Idle (DDR Trap)**: Configures the dedicated network ring buffer within the system memory into an explicit Interrupt Descriptor Table (IDT) Gate (Vector 14 - Page Fault). The isolated CPU cores maintain a 0% compute state under heavy network stress until memory state mutation triggers a hardware interrupt. The handler intercepts the violation address from the `CR2` register and executes a non-blocking `XDP_DROP` mechanism on the NIC.

## Build Requirements

- Rust Nightly (Edition 2024 target toolchain)
- Bare-metal compilation configuration flags: `-C link-arg=-nostartfiles -C link-arg=-nodefaultlibs`

## Repository Structure
- `src/main.rs`: Sterile `no_main` context, IDT descriptors layout, inline assembly x86-64 logic.
- `Cargo.toml`: Package manifests optimized for full binary stripping and LTO execution.
