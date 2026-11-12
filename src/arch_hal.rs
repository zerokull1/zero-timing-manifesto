#![allow(dead_code)]

use core::arch::asm;

/// Чтение аппаратного счётчика тактов с барьером сериализации (x86_64 + ARM64)
#[inline(always)]
pub unsafe fn read_hw_cycles_serialized() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let lo: u32;
        let hi: u32;
        asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack));
        ((hi as u64) << 32) | (lo as u64)
    }

    #[cfg(target_arch = "aarch64")]
    {
        let cnt: u64;
        asm!("isb", "mrs {}, cntvct_el0", out(reg) cnt, options(nomem, nostack));
        cnt
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Нетемпоральная запись 64-битного слова в DDR в обход кэша L1/L2 (x86_64 movnti / ARM64 stnp)
#[inline(always)]
pub unsafe fn stream_write_ddr_u64(dst: *mut u64, val: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        asm!(
            "movnti [{d}], {v}",
            "sfence",
            d = in(reg) dst,
            v = in(reg) val,
            options(nostack)
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        asm!(
            "stnp {v}, {v}, [{d}]",
            "dsb st",
            d = in(reg) dst,
            v = in(reg) val,
            options(nostack)
        );
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        core::ptr::write_volatile(dst, val);
    }
}

/// Безветвящийся выбор значения (x86_64 cmov / ARM64 csel)
#[inline(always)]
pub unsafe fn branchless_select_u64(cond_nonzero: u64, val_if_true: u64, val_if_false: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut res = val_if_false;
        asm!(
            "test {c}, {c}",
            "cmovnz {r}, {t}",
            c = in(reg) cond_nonzero,
            t = in(reg) val_if_true,
            r = inout(reg) res,
            options(pure, nomem, nostack)
        );
        res
    }

    #[cfg(target_arch = "aarch64")]
    {
        let res: u64;
        asm!(
            "cmp {c}, #0",
            "csel {r}, {t}, {f}, ne",
            c = in(reg) cond_nonzero,
            t = in(reg) val_if_true,
            f = in(reg) val_if_false,
            r = out(reg) res,
            options(pure, nomem, nostack)
        );
        res
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        if cond_nonzero != 0 { val_if_true } else { val_if_false }
    }
}
