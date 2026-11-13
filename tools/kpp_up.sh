#!/usr/bin/env bash
set -e
IFACE=${1:-wlp0s20u5}

clang -O2 -g -target bpf -c xdp_shield/zero_dynamic_shield.c -o /tmp/zero_dynamic_shield.o
ip link set dev "$IFACE" xdpgeneric obj /tmp/zero_dynamic_shield.o sec xdp

mkdir -p /sys/fs/bpf/zero_shield
rm -f /sys/fs/bpf/zero_shield/*
bpftool map pin name whitelist_v4 /sys/fs/bpf/zero_shield/whitelist_v4
bpftool map pin name config_map   /sys/fs/bpf/zero_shield/config_map
bpftool map pin name stats_map    /sys/fs/bpf/zero_shield/stats_map

echo "[OK] КПП активен на интерфейсе $IFACE. Управление: sudo ./target/release/zero-ctl"
