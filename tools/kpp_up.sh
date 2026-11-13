#!/usr/bin/env bash
set -e
IFACE=${1:-wlp0s20u5}

clang -O2 -g -target bpf -c xdp_shield/zero_dynamic_shield.c -o /tmp/zero_dynamic_shield.o
ip link set dev "$IFACE" xdp off 2>/dev/null || true

ACTIVE_MODE="NONE"
if ip link set dev "$IFACE" xdpdrv obj /tmp/zero_dynamic_shield.o sec xdp 2>/dev/null; then
    ACTIVE_MODE="DRV_NATIVE (Zero-Copy Ready)"
elif ip link set dev "$IFACE" xdpgeneric obj /tmp/zero_dynamic_shield.o sec xdp 2>/dev/null; then
    ACTIVE_MODE="SKB_GENERIC (Fallback Mode)"
else
    echo "[ERR] Failed to attach XDP on $IFACE"
    exit 1
fi

mkdir -p /sys/fs/bpf/zero_shield
rm -f /sys/fs/bpf/zero_shield/*
echo "$ACTIVE_MODE" > /tmp/zero_xdp_mode.state
bpftool map pin name whitelist_v4 /sys/fs/bpf/zero_shield/whitelist_v4
bpftool map pin name config_map   /sys/fs/bpf/zero_shield/config_map
bpftool map pin name stats_map    /sys/fs/bpf/zero_shield/stats_map
bpftool map pin name events_ring  /sys/fs/bpf/zero_shield/events_ring

echo "[OK] КПП активен на $IFACE | Режим NIC: $ACTIVE_MODE"
