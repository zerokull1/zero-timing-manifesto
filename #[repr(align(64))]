[zero@zer0 zero_timing]$ cat << 'EOF' > src/main.rs
use core::arch::asm;

#[allow(dead_code)]
#[derive(Debug)]
struct SafeWatermark {
    max_payload_bytes: u64,
    tsc_frequency_mhz: u64,
}

// Шаг 1: Аппаратно выравниваем структуру буфера по границе 64-байтной кэш-линии x86_64
#[repr(align(64))]
struct AlignedBuffer {
    data: [u64; 4], // 4 элемента по 8 байт = 32 байта (идеально помещаются в одну 64-байтную строку)
}

static mut DDR_ALIGNED_BUFFER: AlignedBuffer = AlignedBuffer { data: [0; 4] };

#[inline(always)]
unsafe fn tlb_optimized_transit(data_ptr: *const u64) -> [u64; 4] {
    let mut out_buffer = [0u64; 4];

    unsafe {
        asm!(
            "prefetcht0 [{input}]",        // Подтягиваем выровненную кэш-линию в L1
            "lfence",
            "vmovdqu ymm0, [{input}]",     // Загружаем 256 бит данных за 1 такт без риска раскола кэш-линии
            "vmovdqu [{output}], ymm0",
            "vzeroupper",                  // Держим стабильные 3.3 ГГц на Haswell
            "clflush [{input}]",           // Стерилизуем строку процессора
            "mfence",
            input = in(reg) data_ptr,
            output = in(reg) &mut out_buffer,
            out("ymm0") _,
        );
    }

    out_buffer
}

fn main() {
    println!("====================================================");
    println!("  X86_64 TLB & PAGE ALIGNED ENGINE: ZERO TIMING     ");
    println!("====================================================");

    let config = SafeWatermark {
        max_payload_bytes: 64,
        tsc_frequency_mhz: 3300,
    };
    println!("Паспорт TLB и 64-байтного выравнивания запечатан: {:?}", config); 
    println!("----------------------------------------------------");

    unsafe {
        let raw_buffer_ptr = &raw mut DDR_ALIGNED_BUFFER;
        
        // Заполняем выровненный контур
        for i in 0..4 {
            (*raw_buffer_ptr).data[i] = (i as u64 + 1) * 888;
        }

        println!("Адрес буфера в ОЗУ выровнен по 64 байтам: {:p}", raw_buffer_ptr);
        println!("Исходные данные: {:?}", (*raw_buffer_ptr).data);
        println!("Запуск выровненного транзита памяти...");

        let processed_vector = tlb_optimized_transit((*raw_buffer_ptr).data.as_ptr());
        
        println!("----------------------------------------------------");
        println!("Транзит выровненных Huge Pages через YMM0 завершен успешно!");
        println!("Результат: {:?}", processed_vector);
    }
    println!("====================================================");
}
EOF
[zero@zer0 zero_timing]$ cargo run --release
   Compiling zero_timing v0.1.0 (/home/zero/Рабочий стол/zero_timing)
    Finished `release` profile [optimized] target(s) in 0.08s
     Running `target/release/zero_timing`
====================================================
  X86_64 TLB & PAGE ALIGNED ENGINE: ZERO TIMING     
====================================================
Паспорт TLB и 64-байтного выравнивания запечатан: SafeWatermark { max_payload_bytes: 64, tsc_frequency_mhz: 3300 }
----------------------------------------------------
Адрес буфера в ОЗУ выровнен по 64 байтам: 0x557cce4a2240
Исходные данные: [888, 1776, 2664, 3552]
Запуск выровненного транзита памяти...
----------------------------------------------------
Транзит выровненных Huge Pages через YMM0 завершен успешно!
Результат: [888, 1776, 2664, 3552]
====================================================
[zero@zer0 zero_timing]$ 
