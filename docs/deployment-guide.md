# ZERO TIMING: ИНСТРУКЦИЯ ПО РАЗВЕРТЫВАНИЮ КОМПЛЕКСА (ARCH LINUX / RNDIS)

Официальный лог команд для инициализации кремниевой изоляции ядер Haswell, 
BBR-разгона сетевого стека и сборки/инжекции универсального Generic eBPF/XDP капкана.

## ЭТАП 1: Разгон сетевого стека ядра (BBR + FQ) и очистка Plasma от анимаций
Выполнялось в KDE Plasma для снижения Latency и форсирования пропускной способности USB-кабеля.

```bash
# 1. Зашиваем алгоритм контроля очередей BBR и fq намертво в sysctl ядра Linux
sudo sysctl -w net.core.default_qdisc=fq
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
echo -e "net.core.default_qdisc=fq\net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.d/99-sysctl.conf
sudo sysctl --system

# 2. Хирургическое отключение оверхеда и анимаций GTK в Plasma
echo -e "[Settings]\ngtk-enable-animations=0" >> ~/.config/gtk-3.0/settings.ini
echo -e "[Settings]\ngtk-enable-animations=0" >> ~/.config/gtk-4.0/settings.ini
```

## ЭТАП 2: Подготовка гибридного окружения и верификация путей ext4
Определение физических путей и установка легковесного графического движка для ярлыков.

```bash
# 1. Проверка локального кэша и установка утилит отображения стола
sudo pacman -S --needed pcmanfm feh

# 2. Подготовка автозагрузки ярлыков в i3wm (для гибридного контура)
echo "exec --no-startup-id pcmanfm-qt --desktop --profile i3" >> ~/.config/i3/config
sed -i 's/bindsym Mod4+Return exec i3-sensible-terminal/bindsym Mod4+Return exec alacritty/g' ~/.config/i3/config
```

## ЭТАП 3: Локальный bare-metal запуск монолита zero_timing
Взвод Ring 3 демона с аппаратной изоляцией вычислений на Ядрах 1, 2, 3 процессора Haswell через syscall 203.

```bash
# 1. Ручной безопасный пуск монолита на изолированном кремнии (без автозагрузки)
sudo ~/Рабочий\ стол/zero_timing/target/release/zero_timing
```

## ЭТАП 4: Идентификация кабельного линка Xiaomi и компиляция eBPF
Поиск Predictable Network Interface Name мобильного RNDIS-модема и сборка no_std Rust кода.

```bash
# 1. Локализация имени интерфейса USB-кабеля (Цель: enp0s20u11)
ip link show

# 2. Переход в репозиторий и изолированная release-сборка eBPF-капсулы (Edition 2024)
cd ~/Рабочий\ стол/zero_copy_xdp
cargo build --package zero_copy_xdp-ebpf --target bpfel-unknown-none --release -Z build-std=core

# 3. Release-компиляция юзер-агента пространства пользователя с отключением оверхеда логирования
RUSTFLAGS="--cfg aya_log_disable" cargo build --release
```

## ЭТАП 5: Натурный стресс-тест монолита аномальными Null-пакетами
Развертывание локального инжектора сырых байт на интерфейс петли `lo` для проверки `prefetcht0` в кэше L1.

```bash
# 1. Установка низкоуровневого движка конструирования пакетов Scapy
sudo pacman -S --needed python-scapy

# 2. Генерация скрипта инжекции TCP-пакетов со сброшенными флагами (flags=0x00) и сигнатурой 0xBAD000FF
echo -e 'import sys\nfrom scapy.all import *\n\ndef send_null_packet():\n    print("[*] Формирование аномального TCP Null-пакета...")\n    ip_packet = IP(src="127.0.0.1", dst="127.0.0.1")\n    tcp_packet = TCP(sport=12345, dport=80, flags=0x00, seq=1000)\n    payload = b"\\xBA\\xD0\\x00\\xFF" + b"TEST_ATTACK_VECTOR_BYPASS"\n    full_packet = ip_packet / tcp_packet / payload\n    print("[+] Пакет собран. Отправка в интерфейс '\''lo'\''...")\n    send(full_packet, iface="lo", verbose=True)\n    print("[+] Атака произведена. Проверьте логи монолита.")\n\nif __name__ == "__main__":\n    send_null_packet()' > ~/Рабочий\ стол/zero_timing/inject_null.py

# 3. Боевой пуск инжектора сырых байт
sudo python ~/Рабочий\ стол/zero_timing/inject_null.py

# Аварийная команда полной зачистки XDP-хуков с интерфейса (применялась при отладке асимметрии)
# sudo ip link set dev enp0s20u11 xdp off
```

## ЭТАП 6: Финальная интеграция универсального XDP-щита и системная автозагрузка
Накатывание сбалансированного кода (разделение Ingress/Egress) и создание изолированной службы systemd.

```bash
# 1. Создание конфигурационного файла системного сервиса
sudo bash -c 'cat << "EOF" > /etc/systemd/system/zero-copy-xdp.service
[Unit]
Description=Zero-Copy eBPF/XDP Network Bypass Engine
After=network.target

[Service]
Type=simple
ExecStart=/home/zero/Рабочий стол/zero_copy_xdp/target/release/zero_copy_xdp --interface enp0s20u11
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF'

# 2. Перезагрузка планировщика systemd для считывания нового юнита с SSD
sudo systemctl daemon-reload

# 3. Активация автозагрузки демона при старте ПК и мгновенный горячий инжект кода в ОЗУ
sudo systemctl enable --now zero-copy-xdp.service

# 4. Проверка финального статуса маршрутизации и активности eBPF-щита ядра
systemctl status zero-copy-xdp.service
ip route show
```
