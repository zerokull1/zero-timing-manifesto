#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

pub const ZERO_RING_MAGIC: u64 = 0x5A45_524F_5249_4E47; // "ZERORING"
pub const ZERO_RING_CAPACITY: u64 = 65536; // 64K слотов телеметрии в 64MB буфере

/// Кроссплатформенный заголовок кольца памяти (64 байта = 1 кэш-линия).
/// Одинаково читается из UEFI Ring 0, Linux (/dev/mem или /dev/shm) и Windows (PhysicalMemory).
#[repr(C, align(64))]
pub struct ZeroRingHeader {
    pub magic: u64,
    pub version: u32,
    pub cpu_cores_active: u32,
    pub write_idx: AtomicU64,
    pub read_idx: AtomicU64,
    pub blocked_l3_l4_count: AtomicU64,
    pub blocked_l7_count: AtomicU64,
    pub last_entropy_q16: u64,
}

impl ZeroRingHeader {
    #[inline(always)]
    pub unsafe fn init_at(base_addr: usize, cores: u32) -> &'static mut Self {
        let hdr = &mut *(base_addr as *mut Self);
        hdr.magic = ZERO_RING_MAGIC;
        hdr.version = 1;
        hdr.cpu_cores_active = cores;
        hdr.write_idx = AtomicU64::new(0);
        hdr.read_idx = AtomicU64::new(0);
        hdr.blocked_l3_l4_count = AtomicU64::new(0);
        hdr.blocked_l7_count = AtomicU64::new(0);
        hdr.last_entropy_q16 = 0;
        hdr
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.magic == ZERO_RING_MAGIC
    }

    #[inline(always)]
    pub fn publish_slot(&self) -> u64 {
        self.write_idx.fetch_add(1, Ordering::Release) & (ZERO_RING_CAPACITY - 1)
    }
}
