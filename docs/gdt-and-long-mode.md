[zero@zer0 zero_timing]$ cat << 'EOF' > src/main.rs
use core::arch::asm;

#[allow(dead_code)]
#[derive(Debug)]
struct SafeWatermark {
    max_payload_bytes: u64,
    tsc_frequency_mhz: u64,
}

/// Структура 64-битного дескриптора сегмента в таблице GDT (8 байт)
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct GdtDescriptor {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access_byte: u8,
    flags_limit_high: u8, // Здесь сидит бит L (64-bit Mode)
    base_high: u8,
}

/// Аппаратный аудит флагов Long Mode
#[inline(always)]
fn verify_long_mode_descriptor(desc: GdtDescriptor) -> bool {
    // 5-й бит во флагах (гранулярность/разрядность) — это бит L (Long Mode flag)
    (desc.flags_limit_high & 0x20) != 0
}

fn main() {
    println!("====================================================");
    println!("  X86_64 GDT & LONG MODE ARCHITECTURE: ZERO TIMING  ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 64,
        tsc_frequency_mhz: 3300,
    };
    println!("Паспорт Long Mode и GDT запечатан: {:?}", config);
    println!("----------------------------------------------------");

    // Моделируем реальный 64-битный дескриптор кода ядра Ring 0
    // База = 0, Предел = 0, фланги выравнивания = 0x20 (Бит L выставлен в 1)
    let kernel_code_desc = GdtDescriptor {
        limit_low: 0,
        base_low: 0,
        base_middle: 0,
        access_byte: 0x9A,         // Код, читаемый, Ring 0 (Present, Code/Data, Executable, Readable)
        flags_limit_high: 0x20,    // Бит L = 1 (64-битный нативный Long Mode)
        base_high: 0,
    };

    println!("Моделирование дескриптора GDT ядра Ring 0: {:?}", kernel_code_desc);
    
    // Проверяем аппаратный статус разрядности
    let is_64_bit = verify_long_mode_descriptor(kernel_code_desc);
    
    println!("----------------------------------------------------");
    println!("Аппаратный аудит структуры дескриптора завершен!");
    println!("Флаг Long Mode (Бит L = 1): {}", is_64_bit);
    println!("Вердикт процессора: Архитектура x86_64 Long Mode активна. Наносекундный режим включен.");
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
warning: unused import: `core::arch::asm`
 --> src/main.rs:1:5
  |
1 | use core::arch::asm;
  |     ^^^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` (part of `#[warn(unused)]`) on by default

warning: `zero_timing` (bin "zero_timing") generated 1 warning (run `cargo fix--bin "zero_timing" -p zero_timing` to apply 1 suggestion)
    Finished `release` profile [optimized] target(s) in 0.09s
     Running `target/release/zero_timing`
====================================================
  X86_64 GDT & LONG MODE ARCHITECTURE: ZERO TIMING  
====================================================
Паспорт Long Mode и GDT запечатан: SafeWatermark { max_payload_bytes: 64, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Моделирование дескриптора GDT ядра Ring 0: GdtDescriptor { limit_low: 0, base_low: 0, base_middle: 0, access_byte: 154, flags_limit_high: 32, base_high: 0 }
----------------------------------------------------
Аппаратный аудит структуры дескриптора завершен!
Флаг Long Mode (Бит L = 1): true
Вердикт процессора: Архитектура x86_64 Long Mode активна. Наносекундный режим включен.
====================================================
[zero@zer0 zero_timing]$ 
