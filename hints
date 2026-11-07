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

/// Линеаризованный транзит: оптимизируем BTB-предсказатель процессора под плоское выполнение тактов
#[inline(always)]
unsafe fn btb_optimized_transit(data_ptr: *const u64) -> [u64; 4] {
    let mut out_buffer = [0u64; 4];

    unsafe {
        asm!(
            "prefetcht0 [{input}]",        // Шаг 1: Упреждающая выборка кэш-линии
            "lfence",                      // Жесткий барьер спекуляции: фиксируем конвейер предсказателя
            
            "vmovdqu ymm0, [{input}]",     // Шаг 2: Векторный забор 256 бит данных за 1 такт
            "vmovdqu [{output}], ymm0",    // Скидываем результат в буфер назначения
            "vzeroupper",                  // Держим стабильную частоту Haswell на 3.3 ГГц
            
            // Идеальная прямая ветка для BTB-буфера: используем метку 2, обходя баг LLVM #99547
            "jmp 2f",                      // Прямой безусловный прыжок вперед на локальную метку 2
            "nop",                         // Мертвый код для выравнивания конвейера инструкций
            "2:",                          // Точка приземления (локальная метка 2)
            
            "clflush [{input}]",           // Шаг 3: Стерилизуем строку кэша процессора
            "mfence",                      // Полный барьер памяти
            input = in(reg) data_ptr,
            output = in(reg) &mut out_buffer,
            out("ymm0") _,
        );
    }

    out_buffer
}

fn main() {
    println!("====================================================");
    println!("  X86_64 BTB SPECULATION ENGINE: ZERO TIMING        ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 64,
        tsc_frequency_mhz: 3300,
    };
    println!("Паспорт линеаризации ветвлений процессора запечатан: {:?}", config);
    println!("----------------------------------------------------");

    unsafe {
        let raw_buffer_ptr = &raw mut DDR_ALIGNED_BUFFER;
        
        for i in 0..4 {
            (*raw_buffer_ptr).data[i] = (i as u64 + 1) * 1234;
        }

        println!("Адрес выровненного Huge-контура ОЗУ: {:p}", raw_buffer_ptr);
        println!("Запуск транзита под управлением BTB-линеаризации...");

        // Исполняем прыжок с защитой спекулятивного конвейера ЦП
        let processed_vector = btb_optimized_transit((*raw_buffer_ptr).data.as_ptr());
        
        println!("----------------------------------------------------");
        println!("Спекулятивный барьер lfence и BTB-оптимизация завершены!");
        println!("Результат из стерильного конвейера: {:?}", processed_vector); 
    }
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
    Finished `release` profile [optimized] target(s) in 0.07s
     Running `target/release/zero_timing`
====================================================
  X86_64 BTB SPECULATION ENGINE: ZERO TIMING        
====================================================
Паспорт линеаризации ветвлений процессора запечатан: SafeWatermark { max_payload_bytes: 64, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Адрес выровненного Huge-контура ОЗУ: 0x559fc0781240
Запуск транзита под управлением BTB-линеаризации...
----------------------------------------------------
Спекулятивный барьер lfence и BTB-оптимизация завершены!
Результат из стерильного конвейера: [1234, 2468, 3702, 4936]
====================================================
[zero@zer0 zero_timing]$ 
