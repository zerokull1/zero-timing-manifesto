zero@zer0 zero_timing]$ cat << 'EOF' > src/main.rs
use core::arch::asm;

#[allow(dead_code)]
#[derive(Debug)]
struct SafeWatermark {
    max_payload_bytes: u64,
    tsc_frequency_mhz: u64,
}

const VECTOR_SIZE: usize = 4;
static mut DDR_VECTOR_BUFFER: [u64; VECTOR_SIZE] = [0; VECTOR_SIZE];

/// Сквозной обработчик прерывания: проверяет флаги процессора (RFLAGS) на переполнение
#[inline(always)]
unsafe fn interrupt_safe_transit(data_ptr: *const u64) -> (u64, bool) {
    let mut result: u64;
    let mut overflow_triggered: u64 = 0; // Переводим в полный 64-битный формат x86_64

    unsafe {
        asm!(
            "prefetcht0 [{input}]",        // Шаг 1: Подтягиваем кэш-линию в L1 
            "lfence",                      // Ждем завершения выборки
            "mov {out}, [{input}]",        // Шаг 2: Читаем данные напрямую в регистр
            "add {out}, 0",                // Имитируем операцию для выставления RFLAGS
            "jno 2f",                      // x86_64 ветвление: если флага переполнения (OF) нет -> прыгаем на метку 2
            "mov {err}, 1",                // Если волновой сбой деформировал бит -> выставляем флаг ошибки в 64-битном регистре
            "2:",                          // Локальная метка 2
            "clflush [{input}]",           // Шаг 3: Стерилизуем кэш-линию процессора
            "mfence",                      // Железный барьер памяти
            input = in(reg) data_ptr,
            out = out(reg) result,
            err = out(reg) overflow_triggered,
        );
    }

    (result, overflow_triggered == 1)
}

fn main() {
    println!("====================================================");
    println!("  X86_64 INTERRUPT Ring-0 ENGINE: ZERO TIMING       ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 64,
        tsc_frequency_mhz: 3300, // Твой базовый предел
    };
    println!("Паспорт прерываний и RFLAGS запечатан: {:?}", config);
    println!("----------------------------------------------------");

    unsafe {
        let raw_buffer_ptr = &raw mut DDR_VECTOR_BUFFER;
        (*raw_buffer_ptr)[0] = 99999;

        println!("Входящий сетевой пакет в ОЗУ: {}", (*raw_buffer_ptr)[0]);
        println!("Запуск сквозного обработчика прерывания пакета...");

        // Исполняем защищенный транзит с проверкой флагов процессора
        let (packet_data, error_found) = interrupt_safe_transit((*raw_buffer_ptr).as_ptr());
        
        println!("----------------------------------------------------");
        println!("Аппаратный аудит флагов RFLAGS завершен!");
        println!("Данные в регистре: {}, Сигнал деформации (OF): {}", packet_data, error_found);
    }
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
    Finished `release` profile [optimized] target(s) in 0.07s
     Running `target/release/zero_timing`
====================================================
  X86_64 INTERRUPT Ring-0 ENGINE: ZERO TIMING       
====================================================
Паспорт прерываний и RFLAGS запечатан: SafeWatermark { max_payload_bytes: 64, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Входящий сетевой пакет в ОЗУ: 99999
Запуск сквозного обработчика прерывания пакета...
----------------------------------------------------
Аппаратный аудит флагов RFLAGS завершен!
Данные в регистре: 99999, Сигнал деформации (OF): true
====================================================
[zero@zer0 zero_timing]$ 
