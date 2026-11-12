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
        let s0 = self.state;
        for i in 0..7 {
            self.state[i] = self.state[i + 1].rotate_left(11) ^ mix.wrapping_add(i as u64 * 0x9E37_79B9);
        }
        if let (Some(dst), Some(src0)) = (self.state.last_mut(), s0.first()) { *dst = src0.rotate_right(19) ^ mix; }
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Векторное запечатывание 64 байт (512 бит) через парные 256-битные регистры YMM (AVX2):
    /// vpxor (512 бит за 2 такта) + vmovntdq (потоковая запись в DDR мимо кэша без троттлинга AVX-512)
    #[inline(always)]
    pub unsafe fn seal_block_64b(&mut self, src: &[u64; 8], dst_ddr: *mut u64, tsc_now: u64) {
        self.mutate_step(tsc_now);

        #[cfg(target_feature = "avx2")]
        {
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

        #[cfg(not(target_feature = "avx2"))]
        {
            for i in 0..8 {
                let c = src[i] ^ self.state[i];
                asm!("movnti [{d}], {v}", d = in(reg) dst_ddr.add(i), v = in(reg) c, options(nostack));
            }
            asm!("sfence", options(nostack));
        }
    }

    /// 1-тактовая безветвящаяся ловушка самоуничтожения (cmovnz + movnti)
    #[inline(always)]
    pub unsafe fn verify_or_vaporize(&mut self, observed_sig: u64, trap_sink: *mut u64) -> u64 {
        let anomaly = observed_sig ^ self.hw_anchor;
        let ptr = self.state.as_mut_ptr() as u64;
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
        for i in 0..8 {
            self.state[i] &= mask;
        }
        anomaly
    }
}
