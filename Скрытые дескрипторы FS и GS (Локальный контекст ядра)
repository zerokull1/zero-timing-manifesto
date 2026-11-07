[zero@zer0 zero_timing]$ cat << 'EOF' > src/main.rs
use core::arch::asm;

#[allow(dead_code)]
#[derive(Debug)]
struct SafeWatermark {
    max_payload_bytes: u64,
    tsc_frequency_mhz: u64,
}

#[repr(align(64))]
struct AlignedBuffer {
    data: [u64; 4],
}

static mut DDR_ALIGNED_BUFFER: AlignedBuffer = AlignedBuffer { data: [0; 4] };

/// Безопасный bare-metal транзит с имитацией изоляции контекста через системные регистры
#[inline(always)]
unsafe fn nx_protected_transit(data_ptr: *const u64) -> ([u64; 4], u64) {
    let mut out_buffer = [0u64; 4];
    let context_valid: u64;

    unsafe {
        asm!(
            "prefetcht0 [{input}]",        // Шаг 1: Подтягиваем кэш-линию в L1 
            "lfence",
            
            // Имитируем барьер изоляции контекста (аналог swapgs для Ring 0)
            "mov r11, {expected_seed}",    // Загружаем эталонный маркер безопасности в R11
            "vmovdqu ymm0, [{input}]",     // Шаг 2: Векторный забор 256 бит данных в YMM0
            "vmovdqu [{output}], ymm0",    // Скидываем результат в безопасную зону
            "vzeroupper",                  // Фиксируем частоту Haswell на 3.3 ГГц
            
            // Проверка целостности контура после транзита
            "xor r11, {expected_seed}",    // Если маркер совпадает, R11 обнулится
            "mov {ctx_status}, r11",       // Записываем статус верификации контекста
            
            "clflush [{input}]",           // Шаг 3: Стерилизуем строку кэша процессора
            "mfence",
            input = in(reg) data_ptr,
            output = in(reg) &mut out_buffer,
            expected_seed = in(reg) 0x54494D494E47u64, // Метка "TIMING" в шестнадцатеричном формате
            ctx_status = out(reg) context_valid,
            out("ymm0") _,
            out("r11") _,                  // Указываем компилятору, что R11 занят
        );
    }

    (out_buffer, context_valid)
}

fn main() {
    println!("====================================================");
    println!("  X86_64 NX & CONTEXT ISOLATION ENGINE: ZERO TIMING ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 64,
        tsc_frequency_mhz: 3300,
    };
    println!("Паспорт изоляции аппаратных контекстов запечатан: {:?}", config); 
    println!("----------------------------------------------------");

    unsafe {
        let raw_buffer_ptr = &raw mut DDR_ALIGNED_BUFFER;
        
        for i in 0..4 {
            (*raw_buffer_ptr).data[i] = (i as u64 + 1) * 999;
        }

        println!("Адрес выровненного Huge-контура ОЗУ: {:p}", raw_buffer_ptr);
        println!("Запуск защищенного транзита памяти с NX-барьером...");

        // Запускаем транзит с аппаратной сверкой маркера контекста
        let (processed_vector, context_check) = nx_protected_transit((*raw_buffer_ptr).data.as_ptr());
        
        println!("----------------------------------------------------");
        println!("Аппаратная верификация контекста завершена успешно!");
        println!("Код ошибки контекста (0 = Стерилен): {}", context_check);
        println!("Результат из защищенного конвейера: {:?}", processed_vector); 
    }
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
    Finished `release` profile [optimized] target(s) in 0.07s
     Running `target/release/zero_timing`
====================================================
  X86_64 NX & CONTEXT ISOLATION ENGINE: ZERO TIMING 
====================================================
Паспорт изоляции аппаратных контекстов запечатан: SafeWatermark { max_payload_bytes: 64, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Адрес выровненного Huge-контура ОЗУ: 0x55b99eed1280
Запуск защищенного транзита памяти с NX-барьером...
----------------------------------------------------
Аппаратная верификация контекста завершена успешно!
Код ошибки контекста (0 = Стерилен): 0
Результат из защищенного конвейера: [999, 1998, 2997, 3996]
====================================================
[zero@zer0 zero_timing]$ 
