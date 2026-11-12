#![allow(dead_code)]

use core::arch::asm;

/// 1. Аппаратный Watchdog & Circuit Breaker (защита от зависания потребителей без блокировок)
#[repr(C, align(64))]
pub struct HardwareCircuitBreaker {
    pub last_heartbeat_tsc: u64,
    pub timeout_cycles: u64,
    pub trip_count: u64,
    pub is_open: u32,
    pub _pad: [u32; 9],
}

impl HardwareCircuitBreaker {
    #[inline(always)]
    pub const fn new(timeout_cycles: u64) -> Self {
        Self {
            last_heartbeat_tsc: 0,
            timeout_cycles,
            trip_count: 0,
            is_open: 0,
            _pad: [0; 9],
        }
    }

    #[inline(always)]
    pub unsafe fn check_or_trip(&mut self, now_tsc: u64, consumer_alive: bool) -> bool {
        if consumer_alive {
            self.last_heartbeat_tsc = now_tsc;
            self.is_open = 0;
            return true;
        }
        let elapsed = now_tsc.saturating_sub(self.last_heartbeat_tsc);
        if elapsed > self.timeout_cycles {
            if self.is_open == 0 {
                self.trip_count = self.trip_count.wrapping_add(1);
            }
            self.is_open = 1;
            return false;
        }
        self.is_open == 0
    }
}

/// 2. Детерминированный изохронный таймер (Zero-Jitter Spin Pacer с инструкцией CPU pause/yield)
#[inline(always)]
pub unsafe fn pace_until_tsc(target_tsc: u64) {
    loop {
        let (lo, hi): (u32, u32);
        #[cfg(target_arch = "x86_64")]
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        #[cfg(not(target_arch = "x86_64"))]
        { lo = 0; hi = 0; }

        let now = ((hi as u64) << 32) | (lo as u64);
        if now >= target_tsc {
            break;
        }
        #[cfg(target_arch = "x86_64")]
        asm!("pause", options(nomem, nostack));
        #[cfg(target_arch = "aarch64")]
        asm!("yield", options(nomem, nostack));
    }
}

/// 3. Атомарный "Чёрный ящик" (Flight Recorder) в DDR через нетемпоральный movnti
#[repr(C, align(64))]
pub struct BlackboxEvent {
    pub tsc: u64,
    pub event_code: u32,
    pub core_id: u32,
    pub payload_snapshot: [u64; 6],
}

#[inline(always)]
pub unsafe fn record_blackbox_event_ddr(dst_slot: *mut BlackboxEvent, tsc: u64, code: u32, core_id: u32, snap: [u64; 6]) {
    let ev = BlackboxEvent {
        tsc,
        event_code: code,
        core_id,
        payload_snapshot: snap,
    };
    let src_ptr = (&ev as *const BlackboxEvent) as *const u64;
    let dst_ptr = dst_slot as *mut u64;
    for i in 0..8 {
        let word = core::ptr::read_unaligned(src_ptr.add(i));
        #[cfg(target_arch = "x86_64")]
        asm!("movnti [{d}], {v}", d = in(reg) dst_ptr.add(i), v = in(reg) word, options(nostack));
        #[cfg(not(target_arch = "x86_64"))]
        core::ptr::write_volatile(dst_ptr.add(i), word);
    }
    #[cfg(target_arch = "x86_64")]
    asm!("sfence", options(nostack));
}
