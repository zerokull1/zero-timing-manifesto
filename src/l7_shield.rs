// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum L7Verdict {
    CleanPass = 0,
    BlockedHttpSmuggling = 1,
    BlockedInvalidTlsRecord = 2,
    BlockedNullPayload = 3,
}

const SIG_POST_SPACE: u64 = u64::from_le_bytes(*b"POST /  ");
const MASK_5_BYTES: u64   = 0x0000_00FF_FFFF_FFFF;
const SIG_TE_CHUNKED: u64 = u64::from_le_bytes(*b"chunked\r");

/// Аппаратная L7-инспекция на прямом x86_64 ассемблере (без ветвлений и обращений к стеку).
#[inline(always)]
pub unsafe fn inspect_l7_payload_asm(payload: *const u8, len: usize, dst_port: u16) -> L7Verdict { unsafe {
    if len < 16 || payload.is_null() {
        return L7Verdict::BlockedNullPayload;
    }

    let verdict_code: u64;

    if dst_port == 443 {
        // Проверка заголовка TLS Record (байт 0: 0x16/0x17, байт 1: 0x03) без условных переходов
        asm!(
            "mov {q0}, qword ptr [{ptr}]",
            "movzx {b0:e}, {q0:l}",          // rec_type = q0 & 0xFF
            "mov {b1}, {q0}",
            "shr {b1}, 8",
            "movzx {b1:e}, {b1:l}",          // major_ver = (q0 >> 8) & 0xFF
            "xor {res:e}, {res:e}",
            "mov {bad:e}, 2",                // L7Verdict::BlockedInvalidTlsRecord = 2
            "cmp {b1:l}, 0x03",              // TLS major version == 3?
            "cmovne {res:e}, {bad:e}",
            "sub {b0:l}, 0x16",              // 0x16 (Handshake) или 0x17 (AppData) -> 0 или 1
            "cmp {b0:l}, 1",
            "cmova {res:e}, {bad:e}",        // Если > 1 (не 0x16 и не 0x17), ставим код 2
            ptr = in(reg) payload,
            q0 = out(reg) _,
            b0 = out(reg) _,
            b1 = out(reg) _,
            bad = out(reg) _,
            res = out(reg) verdict_code,
            options(readonly, nostack, pure)
        );
    } else {
        // Проверка HTTP Smuggling (POST / в первых 5 байтах + chunked\r во втором qword)
        asm!(
            "mov {q0}, qword ptr [{ptr}]",
            "mov {q1}, qword ptr [{ptr} + 8]",
            "and {q0}, {mask}",
            "xor {res:e}, {res:e}",
            "mov {bad:e}, 1",                // L7Verdict::BlockedHttpSmuggling = 1
            "cmp {q0}, {sig0}",
            "cmovne {bad:e}, {res:e}",       // Сбрасываем bad в 0, если метод не POST /
            "cmp {q1}, {sig1}",
            "cmove {res:e}, {bad:e}",        // Если оба совпали -> res = 1 (BlockedHttpSmuggling)
            ptr = in(reg) payload,
            mask = in(reg) MASK_5_BYTES,
            sig0 = in(reg) (SIG_POST_SPACE & MASK_5_BYTES),
            sig1 = in(reg) SIG_TE_CHUNKED,
            q0 = out(reg) _,
            q1 = out(reg) _,
            bad = out(reg) _,
            res = out(reg) verdict_code,
            options(readonly, nostack, pure)
        );
    }

    core::mem::transmute(verdict_code as u8)
}}

/// Бенчмарк ассемблерного L7-фильтра на TLS 1.3 ClientHello и атаке HTTP Smuggling
pub fn benchmark_l7_swar() -> (u64, u8) {
    let tls_hello: [u8; 16] = [
        0x16, 0x03, 0x03, 0x00, 0xF4, 0x01, 0x00, 0x00,
        0xF0, 0x03, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    ];
    let smuggle_pkt: [u8; 16] = *b"POST /  chunked\r";

    let t0 = crate::tsc::rdtsc_start();
    let v_tls = unsafe { inspect_l7_payload_asm(tls_hello.as_ptr(), tls_hello.len(), 443) };
    let v_atk = unsafe { inspect_l7_payload_asm(smuggle_pkt.as_ptr(), smuggle_pkt.len(), 80) };
    let t1 = crate::tsc::rdtsc_end();

    let combined_code = ((v_tls as u8) << 4) | (v_atk as u8);
    (t1.saturating_sub(t0), combined_code)
}

/// Безветвящийся x86_64 ASM инспектор QUIC / HTTP/3 (UDP 443)
/// Проверяет Long Header (bit 7 = 1), валидность версии (v1/v2) и длину DCID/SCID без ветвлений.
/// Возвращает 0 (Clean QUIC) или 0x04 (BlockedQuicAnomaly).
#[inline(always)]
pub unsafe fn inspect_quic_l7_asm(payload_ptr: *const u8, len: usize) -> u64 { unsafe {
    if len < 16 {
        return 0;
    }

    let q0 = core::ptr::read_unaligned(payload_ptr as *const u64);
    let first_byte = (q0 & 0xFF) as u8;

    // Если это Short Header (bit 7 == 0), пропускаем без проверок Long Header
    if (first_byte & 0x80) == 0 {
        return 0;
    }

    // Версия QUIC находится в байтах 1..5 (Big-Endian)
    let version_be = ((q0 >> 8) & 0xFFFF_FFFF) as u32;
    let version = u32::from_be(version_be);
    let dcid_len = ((q0 >> 40) & 0xFF) as u32;

    let mut verdict: u64 = 0;

    asm!(
        // Проверка на известные версии: QUIC v1 (0x00000001), QUIC v2 (0x6b3343cf) или Version Negotiation (0x00000000)
        "cmp {ver:e}, 1",
        "sete {v1:l}",
        "cmp {ver:e}, 0x6b3343cf",
        "sete {v2:l}",
        "test {ver:e}, {ver:e}",
        "sete {vn:l}",
        "or {v1:l}, {v2:l}",
        "or {v1:l}, {vn:l}",
        // Если ни одна версия не совпала — ставим флаг аномалии 0x04 через cmovz
        "test {v1:l}, {v1:l}",
        "mov {tmp}, 4",
        "cmovz {verd}, {tmp}",
        // По RFC 9000 длина DCID в QUIC v1/v2 не может превышать 20 байт
        "cmp {dcid:e}, 20",
        "cmova {verd}, {tmp}",
        ver = in(reg) version,
        dcid = in(reg) dcid_len,
        v1 = out(reg) _,
        v2 = out(reg) _,
        vn = out(reg) _,
        tmp = out(reg) _,
        verd = inout(reg) verdict,
        options(pure, nomem, nostack)
    );

    verdict
}}
