#![allow(dead_code)]

use core::arch::asm;

#[inline(always)]
pub fn rdtsc_start() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub fn rdtsc_end() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtscp",
            "lfence",
            out("eax") low,
            out("edx") high,
            out("ecx") _,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub fn measure_cycles<F, R>(f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    let start = rdtsc_start();
    let result = f();
    let end = rdtsc_end();
    (result, end.saturating_sub(start))
}
