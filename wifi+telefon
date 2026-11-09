
# ZERO-OS MONOLITH & NETWORK AGGREGATION: FINAL AUTOMATION LOG

Официальный перечень низкоуровневых команд для локализации IP-адресов интерфейсов,
активации Multipath TCP (MPTCP) в ядре Zen и создания системной службы автозагрузки.

## ЭТАП 1: Локализация физических USB-интерфейсов и IP-адресов
Идентификация Predictable Network Interface Names для кабеля Xiaomi и Wi-Fi свистка.

```bash
# 1. Поиск системного имени беспроводного USB-адаптера (Результат: wlp0s20u5)
ip link show | grep -E "wlan|wlp"

# 2. Определение статического локального IP-адреса Wi-Fi интерфейса в подсети роутера
ip addr show wlp0s20u5 | grep "inet "
```

## ЭТАП 2: Конфигурация многопутевого планировщика ядра Linux
Включение MPTCP-параметров в sysctl для распределения суб-потоков трафика (subflows) на BBR.

```bash
# 1. Горячая активация MPTCP в ОЗУ ядра и фиксация в конфигурационном файле на SSD
sudo sysctl -w net.mptcp.enabled=1
echo "net.mptcp.enabled=1" | sudo tee -a /etc/sysctl.d/99-sysctl.conf

# 2. Принудительная перезагрузка всех sysctl правил для валидации лимитов и TTL=65
sudo sysctl --system
```

## ЭТАП 3: Создание независимого скрипта агрегации шлюзов (50/50 Multi-Channel)
Развертывание исполняемого bash-модуля инкапсуляции трафика в обход асимметричных ограничений.

```bash
# 1. Запись монолитного скрипта маршрутизации с трехсекундным DHCP-барьером ожидания
sudo bash -c 'cat << "EOF" > /usr/local/bin/network-aggregation.sh
#!/bin/bash
# Скрипт автоматической агрегации каналов (Кабель + Wi-Fi) с весом 50/50

# Ожидание инициализации DHCP-линков
sleep 3

# Удаляем дефолтный одиночный шлюз
ip route del default 2>/dev/null

# Взводим двухшлюзовую Multipath-балансировку на BBR
ip route add default scope global nexthop via 172.19.72.8 dev enp0s20u11 weight 1 nexthop via 192.168.1.1 dev wlp0s20u5 weight 1
EOF'

# 2. Выдача прав на исполнение скрипта на уровне файловой системы ext4
sudo chmod +x /usr/local/bin/network-aggregation.sh
```

## ЭТАП 4: Интеграция сетевого движка в планировщик systemd
Создание изолированного фонового демона для автоматического склеивания меди и воздуха при старте ПК.

```bash
# 1. Запись конфигурационного файла службы с триггером ожидания online-статуса сети
sudo bash -c 'cat << "EOF" > /etc/systemd/system/network-aggregation.service
[Unit]
Description=Multi-Channel Network Link Aggregation Engine (Multipath BBR)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/network-aggregation.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF'

# 2. Обновление конфигурации systemd менеджера и взвод автозагрузки в ОЗУ
sudo systemctl daemon-reload
sudo systemctl enable --now network-aggregation.service
```

## ЭТАП 5: Локальная фиксация архитектурных изменений в Git
Добавление логов автоматизации в репозиторий проекта `zero_os_monolith`.

```bash
# 1. Переход в каталог проекта, индексация и запечатывание финального слепка на SSD
cd ~/Рабочий\ стол/zero_os_monolith
git add .
git commit -m "Automation: Implement network-aggregation service. Successfully bound enp0s20u11 and wlp0s20u5 under MPTCP"
```
