// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

/// Вердикт детектора раздачи интернета (Zero-Timing Anti-Tethering Engine)
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TetheringVerdict {
    MobileDirect = 0,     // Прямой трафик смартфона (пропускаем)
    TetheringDetected = 1 // Обнаружена раздача / обход TTL (блокируем / режем скорость)
}

/// Безветвящаяся оценка признаков раздачи в одном проходе по заголовкам L3/L4/L7 (~18 тактов)
/// * `ttl` — значение IPv4 TTL
/// * `tcp_win` — размер окна TCP Window (host-endian)
/// * `tcp_mss` — опция TCP MSS (0 если не SYN)
/// * `tls_hello_len` — длина TLS ClientHello (0 если не TLS)
#[inline(always)]
pub fn inspect_tethering_branchless(ttl: u8, tcp_win: u16, tcp_mss: u16, tls_hello_len: u16) -> TetheringVerdict {
    // 1. Классический нескрытый tethering (TTL уменьшен на 1 хоп: 63 или 127)
    let ttl_hop_loss = ((ttl == 63) | (ttl == 127)) as u8;

    // 2. Обход TTL=64 на ноутбуке: десктопный MSS (1460 вместо LTE 1360..1420) + десктопное окно 64240/65535
    let desktop_mss = (tcp_mss >= 1440) as u8;
    let desktop_win = ((tcp_win == 64240) | (tcp_win == 65535)) as u8;

    // 3. Десктопный TLS ClientHello (> 512 байт с характерным десктопным padding/extensions)
    let desktop_tls = (tls_hello_len >= 512) as u8;

    // Суммарный скоринг без ветвлений: >= 2 признаков = раздача на ПК/роутер
    let score = (ttl_hop_loss * 2) + desktop_mss + desktop_win + desktop_tls;
    if score >= 2 {
        TetheringVerdict::TetheringDetected
    } else {
        TetheringVerdict::MobileDirect
    }
}
