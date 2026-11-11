# ZERO-OS MONOLITH: STAGE 0 UEFI EXPLORER DEVELOPMENT LOG

Хронологический список команд для развертывания sterile-контура независимого ядра,
официальной UEFI-линковки компилятора Rust и аппаратного пуска в эмуляторе QEMU.

## ЭТАП 1: Инициализация bare-metal репозитория и конфигурация Cargo
Создание no_std структуры проекта и отключение Ring 3 библиотек.

```bash
# 1. Создание sterile-папки бинарника на Рабочем столе
cd ~/Рабочий\ стол && cargo new zero_os_monolith --bin && cd zero_os_monolith

# 2. Запись манифеста Cargo.toml со статической конфигурацией
cat << "EOF" > Cargo.toml
[package]
name = "zero_os_monolith"
version = "0.1.0"
edition = "2021"

[dependencies]
uefi = "0.24.0"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
EOF
```

## ЭТАП 2: Установка официального UEFI-таргета компилятора
Интеграция сборочных зависимостей core в твой системный тулчейн Arch Linux.

```bash
# 1. Загрузка скомпилированного uefi-компонента через rustup
rustup target add x86_64-unknown-uefi

# 2. Запись жестких аргументов PE-линкера LLD для UEFI архитектуры
mkdir -p .cargo && cat << "EOF" > .cargo/config.toml
[build]
target = "x86_64-unknown-uefi"

[target.x86_64-unknown-uefi]
rustflags = [
    "-C", "link-arg=-nostartfiles",
    "-C", "link-arg=-nodefaultlibs",
]
EOF
```

## ЭТАП 3: Компиляция ядра Stage 0 с кастомным HEX-парсером флагов
Запись ассемблерного кода ввода-вывода (порты 0xCF8/0xCFC) и сборка PE-бинарника.

```bash
# 1. Запись sterile-кода с стековым UTF-16 шестнадцатеричным конвертером
cat << "EOF" > src/main.rs
#![no_std]
#![no_main]

use core::arch::asm;
use uefi::prelude::*;
use uefi::CStr16;

#[inline(always)]
unsafe fn pcie_config_read_u32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xFC)
        | 0x80000000;

    let data: u32;
    asm!(
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        inout("dx") 0x0CF8 => _,
        inout("eax") address => data,
    );
    data
}

fn u32_to_hex_utf16(value: u32, buffer: &mut [u16; 11]) {
    let chars = b"0123456789ABCDEF";
    buffer[0] = '0' as u16;
    buffer[1] = 'x' as u16;
    for i in 0..8 {
        let shift = (7 - i) * 4;
        let nibble = ((value >> shift) & 0xF) as usize;
        buffer[2 + i] = chars[nibble] as u16;
    }
    buffer[10] = 0;
}

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    let stdout = system_table.stdout();
    stdout.reset(false).unwrap();

    stdout.output_string(uefi::cstr16!("\(====================================================\r\\)n")).unwrap();
    stdout.output_string(uefi::cstr16!("  STAGE 0 UEFI EXPLORER: ZERO-OS MONOLITH BOOT      \(\r\\)n")).unwrap();
    stdout.output_string(uefi::cstr16!("\(====================================================\r\\)n")).unwrap();

    unsafe {
        let pcie_device = pcie_config_read_u32(0, 0, 0, 0);
        stdout.output_string(uefi::cstr16!("Host Bridge . ID :                   ")).unwrap();
        
        let mut hex_buffer = [0u16; 11];
        u32_to_hex_utf16(pcie_device, &mut hex_buffer);
        
        let hex_cstr = CStr16::from_u16_with_nul(&hex_buffer).unwrap();
        stdout.output_string(hex_cstr).unwrap();
        
        stdout.output_string(uefi::cstr16!("\(\r\n====================================================\r\\)n")).unwrap();
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
EOF

# 2. Вызов release компилятора и создание независимого BOOTX64.EFI бинарника
cargo build --release
```

## ЭТАП 4: Развертывание виртуального UEFI-полигона (QEMU + OVMF)
Подготовка структуры папок флешки и установка VNC-контура визуализации экрана BIOS.

```bash
# 1. Скачивание базы эмулятора и официальных PE32+ прошивок BIOS Intel
sudo pacman -S --needed qemu-base ovmf tigervnc

# 2. Создание FAT-структуры накопителя EFI System Partition (ESP) на ext4
mkdir -p esp/EFI/BOOT
cp target/x86_64-unknown-uefi/release/zero_os_monolith.efi esp/EFI/BOOT/BOOTX64.EFI

# 3. Холодный запуск виртуального процессора Haswell через pflash диски NVRAM
cp /usr/share/edk2/x64/OVMF_VARS.4m.fd ./OVMF_VARS.fd
qemu-system-x86_64 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
  -drive if=pflash,format=raw,file=./OVMF_VARS.fd \
  -drive format=raw,file=fat:rw:esp \
  -net none

# 4. Подключение к дисплею из соседней вкладки Alacritty (Итоговый вывод: 0x12378086)
vncviewer 127.0.0.1:5900
```

## ЭТАП 5: Конфигурация локальной безопасности Git
Инициализация личности разработчика и фиксация корневого коммита Stage 0 на SSD.

```bash
# 1. Привязка метаданных автора коммитов (Защита от анонимных ошибок Git)
git config --global user.email "zero@zero-timing.net"
git config --global user.name "zero"

# 2. Инициализация Git, скрытие папки target/ и фиксация слепка ассемблерного кода
git init
echo "target/" > .gitignore
git add .
git commit -m "Stage 0: Implement zero-alloc stack UTF-16 HEX parser. Successfully read Host Bridge 0x12378086"
git branch -M main
```
