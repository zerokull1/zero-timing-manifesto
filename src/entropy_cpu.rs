#![allow(dead_code)]

/// Предвычисленная таблица -p * log2(p) в формате фиксированной точки Q16.16
/// для N = 255 интервалов (помещается в одну кэш-линию L1/L2, ноль FPU-инструкций).
const ENTROPY_LUT_Q16: [u32; 256] = {
    let mut lut = [0u32; 256];
    let mut k = 1usize;
    while k < 256 {
        // Аппроксимация -k/255 * log2(k/255) * 65536 для быстрого L1-поиска
        let p_q16 = ((k as u64) << 16) / 255;
        let mut bit = 0u32;
        let mut tmp = 255 / k;
        while tmp > 1 {
            tmp >>= 1;
            bit += 1;
        }
        lut[k] = (p_q16 as u32) * bit;
        k += 1;
    }
    lut
};

/// Анализирует 256 таймстемпов IAT напрямую из выровненной DDR-страницы (Zero-Copy).
/// Возвращает (число_скачков_джиттера, энтропия_в_сотых_долях_бита).
#[inline(always)]
pub fn analyze_ddr_ring_cpu(ring_ptr: *const u64) -> (u32, u32) {
    let mut hist = [0u16; 16];
    let mut jitter_alerts = 0u32;

    unsafe {
        let mut prev = core::ptr::read_volatile(ring_ptr);
        let mut i = 1usize;
        while i < 256 {
            let curr = core::ptr::read_volatile(ring_ptr.add(i));
            let delta = curr.wrapping_sub(prev);
            prev = curr;

            if !(10..=5000).contains(&delta) {
                jitter_alerts += 1;
            }
            let bin = ((delta >> 4) & 0x0F) as usize;
            hist[bin] += 1;
            i += 1;
        }
    }

    let mut total_h_q16 = 0u32;
    let mut b = 0usize;
    while b < 16 {
        let count = hist[b] as usize;
        if count > 0 && count < 256 {
            total_h_q16 += ENTROPY_LUT_Q16[count];
        }
        b += 1;
    }

    // Переводим Q16.16 в сотые доли бита (например, 385 = 3.85 bits)
    let entropy_centibits = (total_h_q16 * 100) >> 16;
    (jitter_alerts, entropy_centibits)
}
