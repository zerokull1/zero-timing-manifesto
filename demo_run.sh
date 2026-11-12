#!/usr/bin/env bash
set -e

echo "================================================================="
echo "  ZERO-TIMING MANIFESTO — ONE-CLICK FULL-STACK VERIFICATION"
echo "================================================================="

echo "[1/5] Building no_std Rust Core (x86_64)..."
cargo build --release --quiet

echo "[2/5] Building Vendor & HFT C-ABI Shared Libraries (.so)..."
rustc --crate-type=cdylib -O -C panic=abort -C lto=yes cisco_daq_plugin/lib.rs -o cisco_daq_plugin/libzero_cisco_daq.so
rustc --crate-type=cdylib -O -C panic=abort -C lto=yes hft_exchange_bridge/lib.rs -o hft_exchange_bridge/libzero_hft_exchange.so
rustc -O ring_reader/zeroring_reader.rs -o ring_reader/zeroring_reader

echo "[3/5] Running Core Hardware Cycle Benchmarks (taskset -c 0)..."
taskset -c 0 ./target/release/zero_project

echo "[4/5] Verifying Cross-Platform ZERORING Telemetry Reader..."
./ring_reader/zeroring_reader

echo "[5/5] Checking Artifacts..."
ls -lh target/release/zero_project cisco_daq_plugin/libzero_cisco_daq.so hft_exchange_bridge/libzero_hft_exchange.so ring_reader/zeroring_reader
echo "================================================================="
echo "  ALL MODULES VERIFIED SUCCESSFULLY!"
echo "================================================================="
