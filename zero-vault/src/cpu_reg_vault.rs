use core::arch::asm;
use crate::mem_guard::wipe_secret;

// Загружаем 256-битный (32 байта) мастер-ключ прямо в регистр YMM15 внутри кристалла CPU
// и мгновенно затираем источник в планке DDR (защита от Cold Boot Attack)
#[target_feature(enable = "avx")]
pub unsafe fn seal_key_in_ymm15(ddr_key: &mut [u8; 32]) {
    asm!(
        "vmovdqu ymm15, [{ptr}]",
        ptr = in(reg) ddr_key.as_ptr(),
        out("ymm15") _,
        options(nostack)
    );
    wipe_secret(ddr_key);
}

// Извлекаем ключ из регистра YMM15 только на время вычисления токена
#[target_feature(enable = "avx")]
pub unsafe fn read_key_from_ymm15(temp_out: &mut [u8; 32]) {
    asm!(
        "vmovdqu [{ptr}], ymm15",
        ptr = in(reg) temp_out.as_mut_ptr(),
        options(nostack)
    );
}

// Мгновенное обнуление регистра YMM15 внутри кремния CPU при выдёргивании USB
#[target_feature(enable = "avx")]
pub unsafe fn wipe_ymm15() {
    asm!("vpxor ymm15, ymm15, ymm15", out("ymm15") _, options(nostack, nomem));
}
