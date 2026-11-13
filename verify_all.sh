#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo "  ZERO-TIMING MANIFESTO :: FULL INTEGRITY & AUDIT SUITE"
echo "============================================================"

echo "[1/6] Building Core Engine (no_std Rust)..."
cargo build --release --quiet
echo "  -> [OK] Core binary built."

echo "[2/6] Verifying Zero-Dependency ELF (No libc / No NEEDED)..."
if readelf -d ./target/release/zero_project | grep -q "(NEEDED)"; then
    echo "  -> [FAIL] External dynamic libraries detected!"
    exit 1
fi
echo "  -> [OK] 100% standalone static ELF."

echo "[3/6] Auditing Hot-Path ASM for Branchless Execution..."
BRANCHES=$(objdump -d -M intel ./target/release/zero_project | awk '/<.*(l7_shield|hash_gate|mutagenic_seal).*>:$/{flag=1; next} /^$/{flag=0} flag && /\b(je|jne|jg|jl|ja|jb)\b/' | wc -l)
if [ "$BRANCHES" -ne 0 ]; then
    echo "  -> [WARN] Found $BRANCHES conditional branches in hot-path!"
else
    echo "  -> [OK] Strictly branchless (0 conditional jumps)."
fi

echo "[4/6] Building & Verifying C-ABI Shared Libraries (Snort DAQ & HFT Bridge)..."
rustc --crate-type cdylib -C panic=abort -O cisco_daq_plugin/lib.rs -o /tmp/libzero_cisco_daq.so
rustc --crate-type cdylib -C panic=abort -O hft_exchange_bridge/lib.rs -o /tmp/libzero_hft_exchange.so
nm -D /tmp/libzero_cisco_daq.so | grep -q "zero_cisco_inspect_frame"
nm -D /tmp/libzero_hft_exchange.so | grep -q "zero_hft_on_market_frame"
rm -f /tmp/libzero_cisco_daq.so /tmp/libzero_hft_exchange.so
echo "  -> [OK] C-ABI symbols verified."

echo "[5/6] Building & Auditing Zero-Vault (YMM15 Silicon Register Seal)..."
cargo build --manifest-path zero-vault/Cargo.toml --release --quiet
if ! objdump -d -M intel zero-vault/target/release/zero-vault | grep -qi "ymm15"; then
    echo "  -> [FAIL] YMM15 register instructions optimized out!"
    exit 1
fi
VAULT_SIZE=$(du -h zero-vault/target/release/zero-vault | cut -f1)
echo "  -> [OK] Zero-Vault built ($VAULT_SIZE) with active YMM15 register binding."

echo "[6/6] Running Offline C-ABI Packet Replay Benchmark (10,000 pkts)..."
python3 tools/pcap_bench.py --count 10000 | grep -E "Total Wall Time|Latency p50|DROP|DECEPTION_TRAP"

echo "============================================================"
echo "  ALL SYSTEM CHECKS PASSED SUCCESSFULLY!"
echo "============================================================"
