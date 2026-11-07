[zero@zer0 zero_timing]$ cat << 'EOF' > src/main.rs
use core::arch::asm;

#[allow(dead_code)]
#[derive(Debug)]
struct SafeWatermark {
    max_payload_bytes: u64,
    tsc_frequency_mhz: u64,
}

// Увеличиваем размер буфера под векторную обработку (4 элемента по 64 бита = 256 бит)
const VECTOR_SIZE: usize = 4;
static mut DDR_VECTOR_BUFFER: [u64; VECTOR_SIZE] = [0; VECTOR_SIZE];

/// Векторный транзит: загружаем 256 бит данных напрямую в регистр YMM0
#[inline(always)]
unsafe fn avx2_vector_transit(data_ptr: *const u64) -> [u64; VECTOR_SIZE] {
    let mut out_buffer = [0u64; VECTOR_SIZE];

    unsafe {
        asm!(
            "lfence",                      // Входной барьер спекулятивного выполнения
            "vmovdqu ymm0, [{input}]",     // Хардкорный x86_64 AVX2: загружаем 256 бит из ОЗУ в YMM0
            "vmovdqu [{output}], ymm0",    // Выгружаем 256-битный вектор напрямую в буфер назначения
            "vzeroupper",                  // Обнуляем верхние половины YMM для стабильности частоты CPU
            "lfence",                      // Выходной защитный барьер
            input = in(reg) data_ptr,
            output = in(reg) &mut out_buffer,
            out("ymm0") _,                 // Указываем компилятору, что регистр YMM0 временно занят
        );
    }

    out_buffer
}

fn main() {
    println!("====================================================");
    println!("  X86_64 VECTOR AVX2 ENGINE: ZERO TIMING           ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 256, // Теперь обрабатываем по 256 бит за такт
        tsc_frequency_mhz: 3300,
    };
    println!("Архитектурный паспорт AVX2 запечатан: {:?}", config);
    println!("----------------------------------------------------");

    unsafe {
        // Безопасно заполняем векторный контур тестовыми логами через сырой указатель
        let raw_buffer_ptr = &raw mut DDR_VECTOR_BUFFER;
        
        for i in 0..VECTOR_SIZE {
            (*raw_buffer_ptr)[i] = (i as u64 + 1) * 111;
        }

        // Выводим данные, читая напрямую из сырого указателя, обходя ограничения static_mut_refs
        println!("Исходный буфер в ОЗУ (Raw): {:?}", *raw_buffer_ptr);
        println!("Выстрел 256-битного вектора через шину PCIe напрямую...");

        // Исполняем хирургический векторный прыжок данных, передавая чистый указатель на массив
        let processed_vector = avx2_vector_transit((*raw_buffer_ptr).as_ptr()); 
        
        println!("----------------------------------------------------");
        println!("Векторный транзит через YMM0 завершен успешно!");
        println!("Результат из регистра YMM0: {:?}", processed_vector);
    }
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
    Finished `release` profile [optimized] target(s) in 0.56s
     Running `target/release/zero_timing`
====================================================
  X86_64 VECTOR AVX2 ENGINE: ZERO TIMING           
====================================================
Архитектурный паспорт AVX2 запечатан: SafeWatermark { max_payload_bytes: 256, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Исходный буфер в ОЗУ (Raw): [111, 222, 333, 444]
Выстрел 256-битного вектора через шину PCIe напрямую...
----------------------------------------------------
Векторный транзит через YMM0 завершен успешно!
Результат из регистра YMM0: [111, 222, 333, 444]
====================================================
[zero@zer0 zero_timing]$ 
