#![allow(dead_code)]

use core::arch::asm;

/// Аппаратный 64-битный CRC32C-хэш (x86_64 SSE4.2 crc32 / ARM64 crc32x) за ~3 такта
#[inline(always)]
pub unsafe fn hw_crc32c_u64(seed: u32, data: u64) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut crc: u64 = seed as u64;
        asm!(
            "crc32 {c}, {d}",
            c = inout(reg) crc,
            d = in(reg) data,
            options(pure, nomem, nostack)
        );
        return crc as u32;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mut crc: u32 = seed;
        asm!(
            "crc32cx {c:w}, {c:w}, {d:x}",
            c = inout(reg) crc,
            d = in(reg) data,
            options(pure, nomem, nostack)
        );
        return crc;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        ((data ^ (seed as u64)).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u32
    }
}

/// Безветвящийся хэш-фильтр: сверяет 16-байтный заголовок/токен с ожидаемым хэшем.
/// Возвращает 1 (PASS), если хэш совпал, или 0 (DROP — в утиль), если не совпал.
#[inline(always)]
pub unsafe fn verify_hash_or_trash(word0: u64, word1: u64, expected_hash: u32, salt: u32) -> u32 {
    let h1 = hw_crc32c_u64(salt, word0);
    let actual_hash = hw_crc32c_u64(h1, word1);
    let diff = actual_hash ^ expected_hash;

    #[cfg(target_arch = "x86_64")]
    {
        let mut verdict: u32 = 1; // 1 = PASS
        let trash: u32 = 0;       // 0 = DROP (в утиль)
        asm!(
            "test {d:e}, {d:e}",
            "cmovnz {v:e}, {t:e}",
            d = in(reg) diff,
            v = inout(reg) verdict,
            t = in(reg) trash,
            options(pure, nomem, nostack)
        );
        return verdict;
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        (diff == 0) as u32
    }
}
