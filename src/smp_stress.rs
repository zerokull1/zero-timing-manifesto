// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicUsize, Ordering};

// Выровненная по 4096 байт структура ядра (исключает False Sharing между кэш-линиями)
#[repr(C, align(4096))]
pub struct AlignedCoreSlot {
    pub packets_processed: u64,
    pub blocked_anomalies: u64,
    pub last_tsc: u64,
    pub dma_sink: u32,
}

static mut RACK_MATRIX: [AlignedCoreSlot; 16] = [const {
    AlignedCoreSlot {
        packets_processed: 0,
        blocked_anomalies: 0,
        last_tsc: 0,
        dma_sink: 0,
    }
}; 16];

static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);
static START_BARRIER: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
unsafe fn sys_mmap_stack(size: usize) -> *mut u8 { unsafe {
    let ret: *mut u8;
    // PROT_READ | PROT_WRITE = 3, MAP_PRIVATE | MAP_ANONYMOUS = 0x22
    asm!(
        "syscall",
        in("rax") 9usize,
        in("rdi") 0usize,
        in("rsi") size,
        in("rdx") 3usize,
        in("r10") 0x22usize,
        in("r8") -1isize,
        in("r9") 0usize,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}}

/// Рабочий цикл одного ядра: 2 500 000 пакетов Active Inline Shield + movnti
extern "C" fn core_worker_loop(core_id: usize) -> ! {
    // Ждем одновременного старта всех потоков
    while START_BARRIER.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }

    let slot = unsafe { &mut RACK_MATRIX[core_id] };
    let mut pkt: u32 = 0x0000_005A; // Аномальный пакет (TTL=90, Flags=0x00)
    let mut count = 0u64;
    let mut blocked = 0u64;

    while count < 2_500_000 {
        let raw = unsafe { core::ptr::read_volatile(&pkt) };
        if (raw & 0xFF) != 65 {
            unsafe { core::ptr::write_volatile(&mut pkt, (raw & !0xFF) | 65); }
            blocked += 1;
        }
        unsafe {
            asm!(
                "movnti [{dst}], {v:e}",
                dst = in(reg) &mut slot.dma_sink,
                v = in(reg) raw,
                options(nostack)
            );
        }
        count += 1;
    }

    unsafe { asm!("sfence", options(nostack)); }
    slot.packets_processed = count;
    slot.blocked_anomalies = blocked;

    ACTIVE_WORKERS.fetch_sub(1, Ordering::Release);
    unsafe {
        asm!("syscall", in("rax") 60usize, in("rdi") 0usize, options(noreturn, nostack));
    }
}

/// Запускает параллельный стресс-тест на `num_threads` ядрах через sys_clone
pub fn run_smp_matrix_stress(num_threads: usize) -> (u64, u64) {
    let threads = num_threads.clamp(1, 16);
    ACTIVE_WORKERS.store(threads, Ordering::SeqCst);
    START_BARRIER.store(0, Ordering::SeqCst);

    // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD = 0x00010F00
    let clone_flags: usize = 0x0001_0F00;

    let mut id = 0usize;
    while id < threads {
        let stack_base = unsafe { sys_mmap_stack(65536) };
        let stack_top = unsafe { stack_base.add(65536) } as usize;

        unsafe {
            asm!(
                "syscall",
                "test rax, rax",
                "jnz 2f",
                "mov rdi, {cid}",
                "call {entry}",
                "2:",
                in("rax") 56usize, // sys_clone
                in("rdi") clone_flags,
                in("rsi") stack_top,
                in("rdx") 0usize,
                in("r10") 0usize,
                in("r8") 0usize,
                cid = in(reg) id,
                entry = sym core_worker_loop,
                out("rcx") _,
                out("r11") _,
                options(nostack)
            );
        }
        id += 1;
    }

    let t0 = crate::tsc::rdtsc_start();
    START_BARRIER.store(1, Ordering::Release);

    while ACTIVE_WORKERS.load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
    let t1 = crate::tsc::rdtsc_end();

    let mut total_pkts = 0u64;
    let mut k = 0usize;
    while k < threads {
        total_pkts += unsafe { RACK_MATRIX[k].packets_processed };
        k += 1;
    }

    (total_pkts, t1.saturating_sub(t0))
}
