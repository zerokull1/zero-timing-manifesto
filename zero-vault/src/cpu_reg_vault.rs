use core::arch::asm;
use crate::mem_guard::wipe_secret;

// Загружаем 256-битный (32 байта) мастер-ключ прямо в регистр YMM15 внутри кристалла CPU
// и мгновенно затираем источник в планке DDR (защита от Cold Boot Attack)
#[no_mangle]
#[inline(never)]
#[target_feature(enable = "avx")]
pub unsafe extern "C" fn seal_key_in_ymm15(ddr_key: &mut [u8; 32]) {
    core::hint::black_box(ddr_key.as_ptr());
    asm!(
        "vmovdqu ymm15, [{ptr}]",
        ptr = in(reg) ddr_key.as_ptr(),
        options(nostack, preserves_flags)
    );
    wipe_secret(ddr_key);
}

// Извлекаем ключ из регистра YMM15 только на время вычисления токена
#[no_mangle]
#[inline(never)]
#[target_feature(enable = "avx")]
pub unsafe extern "C" fn read_key_from_ymm15(temp_out: &mut [u8; 32]) {
    asm!(
        "vmovdqu [{ptr}], ymm15",
        ptr = in(reg) temp_out.as_mut_ptr(),
        options(nostack, preserves_flags)
    );
    core::hint::black_box(temp_out.as_mut_ptr());
}

// Аппаратное обнуление регистра YMM15 при выходе или срабатывании Dead-Man's Switch
#[no_mangle]
#[inline(never)]
#[target_feature(enable = "avx")]
pub unsafe extern "C" fn wipe_ymm15() {
    asm!(
        "vpxor ymm15, ymm15, ymm15",
        options(nostack, preserves_flags)
    );
}
