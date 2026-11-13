#!/usr/bin/env bash
set -e

OUT_DIR=${1:-./dist/zero_gateway_bundle}
mkdir -p "$OUT_DIR"

echo "[1/4] Сборка релизного ядра Rust и библиотек C-ABI..."
cargo build --release
rustc --crate-type cdylib -C panic=abort -O cisco_daq_plugin/lib.rs -o "$OUT_DIR/libzero_cisco_daq.so"
rustc --crate-type cdylib -C panic=abort -O hft_exchange_bridge/lib.rs -o "$OUT_DIR/libzero_hft_exchange.so"

echo "[2/4] Сборка 6.6KB no_std пульта zero-ctl..."
rustc -O -C panic=abort -C target-feature=-sse,-sse2 -C link-arg=-nostartfiles -C link-arg=-static -C strip=symbols tools/zero_ctl.rs -o "$OUT_DIR/zero-ctl" 2>/dev/null

echo "[3/4] Компиляция XDP-щита (VLAN + Rate-Limit + XSKMAP)..."
clang -O2 -g -target bpf -c xdp_shield/zero_dynamic_shield.c -o "$OUT_DIR/zero_dynamic_shield.o"
cp target/release/zero_project "$OUT_DIR/"

echo "[4/4] Генерация автономного пускового скрипта START_GATEWAY.sh..."
cat << 'INNER' > "$OUT_DIR/START_GATEWAY.sh"
#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IFACE=${1:-$(ip -o -4 route show to default | awk '{print $5}' | head -n1)}

if [ -z "$IFACE" ]; then
    echo "[ERR] Не удалось определить сетевой интерфейс. Укажите вручную: sudo ./START_GATEWAY.sh eth0"
    exit 1
fi

ip link set dev "$IFACE" xdp off 2>/dev/null || true
MODE="NONE"
if ip link set dev "$IFACE" xdpdrv obj "$DIR/zero_dynamic_shield.o" sec xdp 2>/dev/null; then
    MODE="DRV_NATIVE (Zero-Copy Ready)"
elif ip link set dev "$IFACE" xdpgeneric obj "$DIR/zero_dynamic_shield.o" sec xdp 2>/dev/null; then
    MODE="SKB_GENERIC (Fallback Mode)"
else
    echo "[ERR] Не удалось подключить XDP на $IFACE"
    exit 1
fi

mkdir -p /sys/fs/bpf/zero_shield
rm -f /sys/fs/bpf/zero_shield/*
bpftool map pin name whitelist_v4 /sys/fs/bpf/zero_shield/whitelist_v4
bpftool map pin name blacklist_v4 /sys/fs/bpf/zero_shield/blacklist_v4
bpftool map pin name config_map   /sys/fs/bpf/zero_shield/config_map
bpftool map pin name stats_map    /sys/fs/bpf/zero_shield/stats_map
bpftool map pin name events_ring  /sys/fs/bpf/zero_shield/events_ring
bpftool map pin name xsks_map     /sys/fs/bpf/zero_shield/xsks_map

"$DIR/zero-ctl" mode enforce
echo "[OK] Zero-Gateway активен на $IFACE | Режим: $MODE"
echo "     Монитор тревог: sudo $DIR/zero-ctl watch"
echo "     Статистика:      sudo $DIR/zero-ctl stats"
INNER

chmod +x "$OUT_DIR/START_GATEWAY.sh"
grep -q "^dist/" .gitignore 2>/dev/null || echo "dist/" >> .gitignore
ls -lh "$OUT_DIR"
