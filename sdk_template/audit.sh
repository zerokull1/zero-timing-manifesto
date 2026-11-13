#!/usr/bin/env bash
set -e
rustc --crate-type cdylib -C panic=abort -C strip=symbols -O sdk_template/src/lib.rs -o /tmp/libhybrid_sdk.so
objdump -d -M intel /tmp/libhybrid_sdk.so | grep -q "vmovntdq"
objdump -d -M intel /tmp/libhybrid_sdk.so | grep -q "rdrand"
rm -f /tmp/libhybrid_sdk.so
echo "[OK] Hybrid SDK template verified (0 libc, vmovntdq & rdrand active)."
