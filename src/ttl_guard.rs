//! Self-Learning Adaptive TTL & DPI-Evasion Guard + Lock-Free IPv4 CIDR Whitelist
//! (`#![no_std]`, Zero-Alloc, Lock-Free, O(1) Q8.8 EMA)

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub const TTL_VERDICT_DROP: u8 = 0;
pub const TTL_VERDICT_PASS: u8 = 1;
pub const TTL_VERDICT_TRAP: u8 = 2;

const TABLE_SIZE: usize = 4096;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const MAX_WHITELIST: usize = 16;

#[repr(C, align(16))]
struct TtlFlowSlot {
    packed_state: AtomicU64,
    anomaly_hits: AtomicU64,
}

impl TtlFlowSlot {
    const fn new() -> Self {
        Self {
            packed_state: AtomicU64::new(0),
            anomaly_hits: AtomicU64::new(0),
        }
    }
}

pub struct SelfLearningTtlGuard {
    slots: [TtlFlowSlot; TABLE_SIZE],
    wl_nets: [AtomicU32; MAX_WHITELIST],
    wl_masks: [AtomicU32; MAX_WHITELIST],
    wl_count: AtomicUsize,
    pub total_checked: AtomicU64,
    pub total_whitelisted: AtomicU64,
    pub total_trapped: AtomicU64,
    pub total_dropped: AtomicU64,
}

impl SelfLearningTtlGuard {
    pub const fn new() -> Self {
        Self {
            slots: [const { TtlFlowSlot::new() }; TABLE_SIZE],
            wl_nets: [const { AtomicU32::new(0) }; MAX_WHITELIST],
            wl_masks: [const { AtomicU32::new(0) }; MAX_WHITELIST],
            wl_count: AtomicUsize::new(0),
            total_checked: AtomicU64::new(0),
            total_whitelisted: AtomicU64::new(0),
            total_trapped: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Добавляет доверенную IPv4-подсеть (network & mask в big-endian) в lock-free белый список.
    #[inline(always)]
    pub fn add_whitelist_cidr(&self, net_be: u32, mask_be: u32) -> bool {
        let idx = self.wl_count.load(Ordering::Acquire);
        if idx >= MAX_WHITELIST {
            return false;
        }
        self.wl_nets[idx].store(net_be & mask_be, Ordering::Release);
        self.wl_masks[idx].store(mask_be, Ordering::Release);
        self.wl_count.store(idx + 1, Ordering::Release);
        true
    }

    #[inline(always)]
    pub fn is_whitelisted(&self, src_ip_be: u32) -> bool {
        let cnt = self.wl_count.load(Ordering::Acquire);
        let mut i = 0;
        while i < cnt {
            let mask = self.wl_masks[i].load(Ordering::Relaxed);
            let net = self.wl_nets[i].load(Ordering::Relaxed);
            if (src_ip_be & mask) == net {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Полная проверка: IPv4 Whitelist -> L3/L4 аномалии -> Самообучающийся Q8.8 EMA профиль TTL.
    #[inline(always)]
    pub fn inspect_packet_ipv4(
        &self,
        src_ip_be: u32,
        dst_ip_be: u32,
        ip_ttl: u8,
        frag_field: u16,
        tcp_flags: u8,
        payload_len: usize,
    ) -> u8 {
        self.total_checked.fetch_add(1, Ordering::Relaxed);

        if self.is_whitelisted(src_ip_be) {
            self.total_whitelisted.fetch_add(1, Ordering::Relaxed);
            return TTL_VERDICT_PASS;
        }

        let is_zero_ttl = (ip_ttl == 0) as u8;
        let has_more_frags = (frag_field & 0x2000) != 0;
        let frag_offset = frag_field & 0x1FFF;
        let is_tiny_frag_evasion = ((has_more_frags || frag_offset > 0) && payload_len < 64) as u8;

        let syn_fin = (tcp_flags & 0x03) == 0x03;
        let xmas = (tcp_flags & 0x29) == 0x29;
        let bad_tcp = (syn_fin || xmas) as u8;

        if (is_zero_ttl | is_tiny_frag_evasion | bad_tcp) != 0 {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return TTL_VERDICT_DROP;
        }

        let flow_hash = ((src_ip_be as u64) << 32) ^ (dst_ip_be as u64) ^ 0x9E3779B97F4A7C15u64;
        let idx = (flow_hash as usize) & TABLE_MASK;
        let tag = (flow_hash >> 32) as u32;
        let slot = &self.slots[idx];

        let prev = slot.packed_state.load(Ordering::Acquire);
        let prev_tag = (prev >> 32) as u32;
        let ttl_q8 = (ip_ttl as u32) << 8;

        if prev_tag != tag || prev == 0 {
            let new_state = ((tag as u64) << 32)
                | ((ttl_q8 as u64) << 16)
                | (6u64 << 8)
                | 1u64;
            slot.packed_state.store(new_state, Ordering::Release);
            return TTL_VERDICT_PASS;
        }

        let base_ttl_q8 = ((prev >> 16) & 0xFFFF) as u32;
        let base_ttl = (base_ttl_q8 >> 8) as i32;
        let curr_ttl = ip_ttl as i32;
        let dyn_thresh = ((prev >> 8) & 0xFF) as i32;
        let confidence = (prev & 0xFF) as u32;

        let delta = (curr_ttl - base_ttl).abs();
        if delta > dyn_thresh {
            slot.anomaly_hits.fetch_add(1, Ordering::Relaxed);
            self.total_trapped.fetch_add(1, Ordering::Relaxed);
            return TTL_VERDICT_TRAP;
        }

        let updated_ttl_q8 = ((base_ttl_q8 * 15) + ttl_q8) >> 4;
        let next_conf = if confidence < 255 { confidence + 1 } else { 255 };
        let next_thresh: u32 = if next_conf > 64 && delta <= 1 {
            3
        } else if next_conf > 16 && delta <= 2 {
            4
        } else {
            dyn_thresh as u32
        };

        let updated_state = ((tag as u64) << 32)
            | ((updated_ttl_q8 as u64) << 16)
            | ((next_thresh as u64) << 8)
            | (next_conf as u64);

        slot.packed_state.store(updated_state, Ordering::Release);
        TTL_VERDICT_PASS
    }
}

pub static GLOBAL_TTL_GUARD: SelfLearningTtlGuard = SelfLearningTtlGuard::new();
