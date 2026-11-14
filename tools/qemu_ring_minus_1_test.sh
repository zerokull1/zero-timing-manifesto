#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/uefi_stage0"

cargo build --release

TMP_BOOT="$(mktemp -d /tmp/ztm_efi_boot.XXXXXX)"
trap 'rm -rf "$TMP_BOOT"' EXIT

mkdir -p "$TMP_BOOT/EFI/BOOT"
cp target/x86_64-unknown-uefi/release/zero_os_monolith.efi "$TMP_BOOT/EFI/BOOT/BOOTX64.EFI"
printf 'FS0:\r\nEFI\\BOOT\\BOOTX64.EFI\r\n' > "$TMP_BOOT/startup.nsh"

qemu-system-x86_64 \
  -enable-kvm \
  -cpu host,+vmx \
  -m 256M \
  -bios /usr/share/edk2/x64/OVMF.4m.fd \
  -drive format=raw,file="fat:rw:$TMP_BOOT" \
  -netdev user,id=net0 \
  -device e1000,netdev=net0,romfile="" \
  -serial stdio \
  -display none \
  -no-reboot
