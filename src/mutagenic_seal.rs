// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;

#[repr(C, align(64))]
pub struct MutagenicKey512 {
    pub state: [u64; 8],
    pub hw_anchor: u64,
    pub epoch: u64,
}

impl MutagenicKey512 {
    #[inline(always)]
    pub const fn new(seed: [u64; 8], hw_anchor: u64) -> Self {
        Self { state: seed, hw_anchor, epoch: 0 }
    }

    #[inline(always)]
    pub unsafe fn mutate_step(&mut self, tsc_now: u64) {
        let mix = tsc_now ^ self.hw_anchor.rotate_left((self.epoch & 63) as u32);
        self.state.rotate_left(1);
        for (idx, word) in self.state.iter_mut().enumerate() {
            *word = word.rotate_left(13) ^ mix.wrapping_add((idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        }
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Векторное запечатывание 64 байт (512 бит) в DDR:
    /// Использует AVX2 vmovntdq при 32-байтном выравнивании dst_ddr (без риска #GP) и movnti как откат.
    #[inline(always)]
    pub unsafe fn seal_block_64b(&mut self, src: &[u64; 8], dst_ddr: *mut u64, tsc_now: u64) { unsafe {
        self.mutate_step(tsc_now);

        #[cfg(target_feature = "avx2")]
        if (dst_ddr as usize & 31) == 0 {
            asm!(
                "vmovdqu ymm0, [{s}]",
                "vmovdqu ymm1, [{s} + 32]",
                "vpxor ymm0, ymm0, [{k}]",
                "vpxor ymm1, ymm1, [{k} + 32]",
                "vmovntdq [{d}], ymm0",
                "vmovntdq [{d} + 32], ymm1",
                "sfence",
                s = in(reg) src.as_ptr(),
                k = in(reg) self.state.as_ptr(),
                d = in(reg) dst_ddr,
                out("ymm0") _,
                out("ymm1") _,
                options(nostack)
            );
            return;
        }

        for (i, (s_word, k_word)) in src.iter().zip(self.state.iter()).enumerate() {
            let c = *s_word ^ *k_word;
            #[cfg(target_arch = "x86_64")]
            asm!("movnti [{d}], {v}", d = in(reg) dst_ddr.add(i), v = in(reg) c, options(nostack));
            #[cfg(not(target_arch = "x86_64"))]
            core::ptr::write_volatile(dst_ddr.add(i), c);
        }
        #[cfg(target_arch = "x86_64")]
        asm!("sfence", options(nostack));
    }}

    /// 1-тактовая безветвящаяся ловушка самоуничтожения (cmovnz + movnti)
    #[inline(always)]
    pub unsafe fn verify_or_vaporize(&mut self, observed_sig: u64, trap_sink: *mut u64) -> u64 { unsafe {
        let anomaly = observed_sig ^ self.hw_anchor;
        let ptr = self.state.as_mut_ptr() as u64;
        #[cfg(target_arch = "x86_64")]
        asm!(
            "test {a}, {a}",
            "cmovnz {p}, {t}",
            "movnti [{p}], {z}",
            "sfence",
            a = in(reg) anomaly,
            t = in(reg) trap_sink as u64,
            z = in(reg) 0u64,
            p = in(reg) ptr,
            options(nostack)
        );
        let mask = if anomaly == 0 { u64::MAX } else { 0 };
        for word in self.state.iter_mut() {
            *word &= mask;
        }
        anomaly
    }}
}
