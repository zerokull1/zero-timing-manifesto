# Mutagen Wire Module (`mutagen_wire_mod`)

Автономный подключаемый модуль прозрачной L2/L3 мутации трафика на кромке сетевого интерфейса (`eBPF XDP`) с горячим переключением по требованию.

## Принцип работы
* **Штатный режим (`off` / bypass):** нулевой оверхед (`XDP_PASS`), трафик идёт открытым стандартным потоком.
* **Активный режим (`on <hex_seed>`):** скользящая 64-битная потоковая мутация L7-нагрузки на выходе (`derive_stream_key` от общего `Seed` + IP-адресов + `IP ID`) и мгновенная обратная демутация на входе приёмной стойки до попадания пакета в сетевой стек Linux.

## Сборка и управление
```bash
make
# Подключение к интерфейсу и привязка карты конфигурации:
sudo ip link set dev eth0 xdp obj mutagen_kern.o sec xdp
sudo bpftool map pin name mutagen_cfg /sys/fs/bpf/mutagen_cfg

# Горячее переключение без обрыва соединений:
sudo MUTAGEN_PIN=/sys/fs/bpf/mutagen_cfg ./mutagen-ctl on 0xDEADBEEFCAFE1337
sudo MUTAGEN_PIN=/sys/fs/bpf/mutagen_cfg ./mutagen-ctl status
sudo MUTAGEN_PIN=/sys/fs/bpf/mutagen_cfg ./mutagen-ctl off
```
