//! Self-Learning Adaptive TTL & DPI-Evasion Guard (`#![no_std]`, Zero-Alloc, Lock-Free)
//!
//! Автоматически обучает базовый профиль TTL каждого сетевого маршрута (Q8.8 EMA)
//! и детектирует попытки обхода DPI (TTL Insertion, TCP RST-инъекции, Tiny Fragments)
//! без блокировок, без плавающей точки и с защитой базовой линии от отравления.

use core::sync::atomic::{AtomicU64, Ordering};

pub const TTL_VERDICT_DROP: u8 = 0;
pub const TTL_VERDICT_PASS: u8 = 1;
pub const TTL_VERDICT_TRAP: u8 = 2;

const TABLE_SIZE: usize = 4096;
const TABLE_MASK: usize = TABLE_SIZE - 1;

/// 16-байтный lock-free слот состояния маршрута (4 слота ровно в 64-байтную кэш-линию)
#[repr(C, align(16))]
struct TtlFlowSlot {
    /// Упакованное состояние:
    /// [63:32] = flow_tag (верхние 32 бита flow_hash)
    /// [31:16] = ttl_ema (Q8.8: реальный TTL * 256)
    /// [15:8]  = dynamic_threshold (адаптивный порог отклонения в хопах)
    /// [7:0]   = confidence (счётчик доверия маршруту, 0..255)
    packed_state: AtomicU64,
    /// Счётчик пойманных аномалий по данному слоту
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
    pub total_checked: AtomicU64,
    pub total_trapped: AtomicU64,
    pub total_dropped: AtomicU64,
}

impl SelfLearningTtlGuard {
    pub const fn new() -> Self {
        const EMPTY_SLOT: TtlFlowSlot = TtlFlowSlot::new();
        Self {
            slots: [EMPTY_SLOT; TABLE_SIZE],
            total_checked: AtomicU64::new(0),
            total_trapped: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Инспекция и онлайн-обучение профиля TTL в реальном времени.
    ///
    /// * `flow_hash` — 64-битный хэш пары (src_ip, dst_ip)
    /// * `ip_ttl` — текущий TTL из IPv4 заголовка (или Hop Limit из IPv6)
    /// * `frag_field` — 16-битное поле Flags + Fragment Offset из IPv4 (в host byte order)
    /// * `tcp_flags` — байт флагов TCP (0, если UDP/ICMP)
    /// * `payload_len` — длина L4/L7 полезной нагрузки
    #[inline(always)]
    pub fn inspect_and_learn(
        &self,
        flow_hash: u64,
        ip_ttl: u8,
        frag_field: u16,
        tcp_flags: u8,
        payload_len: usize,
    ) -> u8 {
        self.total_checked.fetch_add(1, Ordering::Relaxed);

        // 1. Мгновенная проверка критических аномалий L3/L4 (TTL=0, Tiny Fragment Evasion, Xmas/Null/SYN+FIN)
        let is_zero_ttl = (ip_ttl == 0) as u8;
        let has_more_frags = (frag_field & 0x2000) != 0;
        let frag_offset = frag_field & 0x1FFF;
        // Попытка разорвать L7-заголовок (TLS ClientHello / HTTP) мелким фрагментом для обхода DPI
        let is_tiny_frag_evasion = ((has_more_frags || frag_offset > 0) && payload_len < 64) as u8;

        // Запрещённые комбинации TCP-флагов (SYN+FIN, Xmas FIN+PSH+URG, Null-скан)
        let syn_fin = (tcp_flags & 0x03) == 0x03;
        let xmas = (tcp_flags & 0x29) == 0x29;
        let bad_tcp = (syn_fin || xmas) as u8;

        if (is_zero_ttl | is_tiny_frag_evasion | bad_tcp) != 0 {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return TTL_VERDICT_DROP;
        }

        // 2. Поиск слота маршрута без блокировок
        let idx = (flow_hash as usize) & TABLE_MASK;
        let tag = (flow_hash >> 32) as u32;
        let slot = &self.slots[idx];

        let prev = slot.packed_state.load(Ordering::Acquire);
        let prev_tag = (prev >> 32) as u32;
        let ttl_q8 = (ip_ttl as u32) << 8;

        // Новый или вытесненный маршрут: инициализируем базовую линию (Zero-Config Baseline)
        if prev_tag != tag || prev == 0 {
            let init_thresh: u32 = 6; // Стартовый допуск +-6 хопов до накопления статистики
            let init_conf: u32 = 1;
            let new_state = ((tag as u64) << 32)
                | ((ttl_q8 as u64) << 16)
                | ((init_thresh as u64) << 8)
                | (init_conf as u64);
            slot.packed_state.store(new_state, Ordering::Release);
            return TTL_VERDICT_PASS;
        }

        // 3. Сравнение текущего TTL с обученным EMA-профилем маршрута
        let base_ttl_q8 = ((prev >> 16) & 0xFFFF) as u32;
        let base_ttl = (base_ttl_q8 >> 8) as i32;
        let curr_ttl = ip_ttl as i32;
        let dyn_thresh = ((prev >> 8) & 0xFF) as i32;
        let confidence = (prev & 0xFF) as u32;

        let delta = (curr_ttl - base_ttl).abs();

        // Аномальный скачок TTL (TTL Insertion Evasion / Spoofed RST Injection):
        // Отправляем в Deception Trap и НЕ обновляем базовую линию (защита от отравления модели)
        if delta > dyn_thresh {
            slot.anomaly_hits.fetch_add(1, Ordering::Relaxed);
            self.total_trapped.fetch_add(1, Ordering::Relaxed);
            return TTL_VERDICT_TRAP;
        }

        // 4. Онлайн-адаптация модели (EMA с весом 15/16) и сужение коридора допуска при стабильном канале
        let updated_ttl_q8 = ((base_ttl_q8 * 15) + ttl_q8) >> 4;
        let next_conf = if confidence < 255 { confidence + 1 } else { 255 };

        // После 64 стабильных пакетов сужаем допуск до 3 хопов, чтобы ловить даже тонкий спуфинг
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

/// Глобальный lock-free экземпляр самообучающегося TTL-стража для Data-Plane
pub static GLOBAL_TTL_GUARD: SelfLearningTtlGuard = SelfLearningTtlGuard::new();
