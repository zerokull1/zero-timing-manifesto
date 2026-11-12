#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

pub const FLOW_TABLE_BUCKETS: usize = 65536; // Степень двойки для быстрой битовой маски (& 0xFFFF)

/// Слот активного сетевого потока (ровно 64 байта = 1 кэш-линия процессора, Zero False-Sharing).
#[repr(C, align(64))]
pub struct FlowSlot {
    pub flow_hash: AtomicU64,   // 64-битный хэш 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Proto)
    pub pkt_count: AtomicU64,   // Счётчик пакетов в сессии
    pub byte_count: AtomicU64,  // Счётчик байт в сессии
    pub last_tsc: AtomicU64,    // Аппаратная метка времени (TSC) последнего пакета
    pub flags: AtomicU64,       // Битовая маска состояния (0x01 = Verified, 0x02 = Suspicious, 0x04 = Blocked)
    pub _pad: [u64; 3],
}

impl FlowSlot {
    pub const fn new() -> Self {
        Self {
            flow_hash: AtomicU64::new(0),
            pkt_count: AtomicU64::new(0),
            byte_count: AtomicU64::new(0),
            last_tsc: AtomicU64::new(0),
            flags: AtomicU64::new(0),
            _pad: [0; 3],
        }
    }
}

/// Безблокировочное обновление состояния потока в DDR за один проход CAS (lock cmpxchg)
#[inline(always)]
pub unsafe fn track_flow_lockfree(
    table_ptr: *const FlowSlot,
    flow_hash: u64,
    pkt_len: u64,
    now_tsc: u64,
) -> u64 {
    let idx = (flow_hash as usize) & (FLOW_TABLE_BUCKETS - 1);
    let slot = &*table_ptr.add(idx);

    let current_hash = slot.flow_hash.load(Ordering::Acquire);
    if current_hash == flow_hash {
        slot.pkt_count.fetch_add(1, Ordering::Relaxed);
        slot.byte_count.fetch_add(pkt_len, Ordering::Relaxed);
        slot.last_tsc.store(now_tsc, Ordering::Release);
        return slot.flags.load(Ordering::Acquire);
    }

    // Если слот пуст или устарел (> 3 млрд тактов ~ 1 сек) — захватываем его без блокировок
    let last = slot.last_tsc.load(Ordering::Relaxed);
    if current_hash == 0 || now_tsc.saturating_sub(last) > 3_000_000_000 {
        if slot
            .flow_hash
            .compare_exchange(current_hash, flow_hash, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.pkt_count.store(1, Ordering::Relaxed);
            slot.byte_count.store(pkt_len, Ordering::Relaxed);
            slot.flags.store(0, Ordering::Relaxed);
            slot.last_tsc.store(now_tsc, Ordering::Release);
            return 0;
        }
    }

    0
}
