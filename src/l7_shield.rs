#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum L7Verdict {
    CleanPass = 0,
    BlockedHttpSmuggling = 1,
    BlockedInvalidTlsRecord = 2,
    BlockedNullPayload = 3,
    BlockedTlsRecordSplitting = 4,
}

const SIG_POST_SPACE: u64 = u64::from_le_bytes(*b"POST /  ");
const MASK_5_BYTES: u64   = 0x0000_00FF_FFFF_FFFF;
const SIG_TE_CHUNKED: u64 = u64::from_le_bytes(*b"chunked\r");

/// Аппаратная L7-инспекция на прямом x86_64 ассемблере (без ветвлений и обращений к стеку).
/// Детектирует:
/// - Невалидные TLS-заголовки (код 2)
/// - TLS Record Splitting / Micro-Fragmentation: Handshake 0x16 с record_len < 40 байт (код 4)
/// - HTTP Request Smuggling: POST / + chunked (код 1)
#[inline(always)]
pub unsafe fn inspect_l7_payload_asm(payload: *const u8, len: usize, dst_port: u16) -> L7Verdict { unsafe {
    if len < 16 || payload.is_null() {
        return L7Verdict::BlockedNullPayload;
    }

    let verdict_code: u64;

    if dst_port == 443 {
        asm!(
            "mov {q0}, qword ptr [{ptr}]",
            "movzx {b0:e}, {q0:l}",          // rec_type = q0 & 0xFF
            "mov {b1}, {q0}",
            "shr {b1}, 8",
            "movzx {b1:e}, {b1:l}",          // major_ver = (q0 >> 8) & 0xFF

            // Извлекаем record_len (байты 3..5 в Big-Endian -> биты 24..40 в q0)
            "mov {rlen}, {q0}",
            "shr {rlen}, 24",
            "rol {rlen:x}, 8",               // bswap16: перевод record_len из BE в LE

            "xor {res:e}, {res:e}",
            "mov {bad:e}, 2",                // L7Verdict::BlockedInvalidTlsRecord = 2
            "mov {split:e}, 4",              // L7Verdict::BlockedTlsRecordSplitting = 4

            // Проверка TLS Record Splitting: если rec_type == 0x16 (Handshake) И record_len < 40
            "cmp {rlen:x}, 40",
            "setb {is_small:l}",             // is_small = 1 если record_len < 40
            "cmp {b0:l}, 0x16",
            "sete {is_hs:l}",                // is_hs = 1 если Handshake (0x16)
            "and {is_small:l}, {is_hs:l}",
            "test {is_small:l}, {is_small:l}",
            "cmovnz {res:e}, {split:e}",     // Если Handshake && record_len < 40 -> код 4

            // Проверка базовой валидности TLS: major_ver == 0x03 и rec_type in {0x16, 0x17}
            "cmp {b1:l}, 0x03",
            "cmovne {res:e}, {bad:e}",
            "sub {b0:l}, 0x16",              // 0x16 -> 0, 0x17 -> 1
            "cmp {b0:l}, 1",
            "cmova {res:e}, {bad:e}",

            ptr = in(reg) payload,
            q0 = out(reg) _,
            b0 = out(reg) _,
            b1 = out(reg) _,
            rlen = out(reg) _,
            bad = out(reg) _,
            split = out(reg) _,
            is_small = out(reg) _,
            is_hs = out(reg) _,
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

    match verdict_code as u8 {
        0 => L7Verdict::CleanPass,
        1 => L7Verdict::BlockedHttpSmuggling,
        2 => L7Verdict::BlockedInvalidTlsRecord,
        4 => L7Verdict::BlockedTlsRecordSplitting,
        _ => L7Verdict::BlockedNullPayload,
    }
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
/// Проверяет:
/// - Long Header (bit 7 = 1)
/// - Валидность версии (QUIC v1, QUIC v2, Version Negotiation)
/// - Длину DCID <= 20 байт (RFC 9000)
/// - Защиту от QUIC Initial < 1200 байт (RFC 9000 Section 14.1 Anti-Amplification / DPI Evasion)
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
    let pkt_type = ((first_byte >> 4) & 0x03) as u32;
    let pkt_len = len as u32;

    let mut verdict: u64 = 0;

    asm!(
        // Проверка на известные версии: QUIC v1 (1), QUIC v2 (0x6b3343cf) или Version Negotiation (0)
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

        // RFC 9000 Section 14.1: пакет QUIC Initial обязан быть >= 1200 байт
        // Для v1 Initial == 0, для v2 (0x6b3343cf) Initial == 1 (то есть pkt_type == v2)
        "cmp {ptype:e}, {v2:e}",
        "sete {is_init:l}",
        "cmp {plen:e}, 1200",
        "setb {is_short_init:l}",
        "and {is_init:l}, {is_short_init:l}",
        "test {is_init:l}, {is_init:l}",
        "cmovnz {verd}, {tmp}",

        ver = in(reg) version,
        dcid = in(reg) dcid_len,
        ptype = in(reg) pkt_type,
        plen = in(reg) pkt_len,
        v1 = out(reg) _,
        v2 = out(reg) _,
        vn = out(reg) _,
        is_init = out(reg) _,
        is_short_init = out(reg) _,
        tmp = out(reg) _,
        verd = inout(reg) verdict,
        options(pure, nomem, nostack)
    );

    verdict
}}

/// Проверка аппаратной поддержки AVX-512F + AVX-512BW и разрешения в XCR0 (ZMM0..ZMM31)
#[inline(always)]
pub unsafe fn cpu_supports_avx512bw() -> bool { unsafe {
    let ecx1: u32;
    asm!(
        "push rbx",
        "mov eax, 1",
        "cpuid",
        "pop rbx",
        out("ecx") ecx1,
        out("eax") _,
        out("edx") _,
        options(nomem, nostack)
    );
    // Проверяем OSXSAVE (bit 27)
    if (ecx1 & (1 << 27)) == 0 {
        return false;
    }

    // Проверяем XCR0: биты SSE(1), AVX(2), OPMASK(5), ZMM_HI256(6), HI16_ZMM(7) -> маска 0xE6
    let xcr0_lo: u32;
    asm!("xor ecx, ecx", "xgetbv", out("eax") xcr0_lo, out("edx") _, out("ecx") _, options(nomem, nostack));
    if (xcr0_lo & 0xE6) != 0xE6 {
        return false;
    }

    // CPUID.(EAX=07H, ECX=0):EBX -> AVX512F (bit 16) + AVX512BW (bit 30)
    let ebx7: u32;
    asm!(
        "push rbx",
        "mov eax, 7",
        "xor ecx, ecx",
        "cpuid",
        "mov {out_ebx:e}, ebx",
        "pop rbx",
        out_ebx = out(reg) ebx7,
        out("eax") _,
        out("ecx") _,
        out("edx") _,
        options(nomem, nostack)
    );
    let mask = (1 << 16) | (1 << 30);
    (ebx7 & mask) == mask
}}

/// Поиск сигнатуры 'c' (0x63, начало "chunked\r") сразу по всей 64-байтной кэш-линии L1 через AVX-512 (zmm0).
/// Возвращает 64-битную битовую маску совпадений (1 бит = 1 байт в кэш-линии).
#[target_feature(enable = "avx512f,avx512bw")]
#[inline]
pub unsafe fn scan_cacheline_byte_avx512(ptr: *const u8, needle: u8) -> u64 { unsafe {
    let mask64: u64;
    let needle_broadcast: u32 = (needle as u32) * 0x0101_0101;
    asm!(
        "vmovd {xmm_tmp}, {ndl:e}",
        "vpbroadcastd zmm1, {xmm_tmp}",
        "vmovdqu64 zmm0, zmmword ptr [{p}]",
        "vpcmpeqb k1, zmm0, zmm1",
        "kmovq {out_mask}, k1",
        "vzeroupper",
        p = in(reg) ptr,
        ndl = in(reg) needle_broadcast,
        xmm_tmp = out(xmm_reg) _,
        out_mask = out(reg) mask64,
        out("zmm0") _,
        out("zmm1") _,
        out("k1") _,
        options(nostack)
    );
    mask64
}}

/// Всеядный стоечный L7-инспектор:
/// На Intel Xeon Scalable / AMD EPYC Zen 4/5 ускоряет поиск HTTP Smuggling по 64-байтной кэш-линии через AVX-512,
/// на Haswell / VM без AVX-512 бесшовно исполняет 64-битный GPR fast-path.
#[inline(always)]
pub unsafe fn inspect_l7_payload_adaptive(payload: *const u8, len: usize, dst_port: u16) -> L7Verdict { unsafe {
    if dst_port == 80 && len >= 64 && !payload.is_null() && cpu_supports_avx512bw() {
        let q0 = (payload as *const u64).read_unaligned();
        if (q0 & MASK_5_BYTES) == (SIG_POST_SPACE & MASK_5_BYTES) {
            let mut hits = scan_cacheline_byte_avx512(payload, b'c');
            while hits != 0 {
                let idx = hits.trailing_zeros() as usize;
                if idx + 8 <= 64 {
                    let cand = (payload.add(idx) as *const u64).read_unaligned();
                    if cand == SIG_TE_CHUNKED {
                        return L7Verdict::BlockedHttpSmuggling;
                    }
                }
                hits &= hits - 1;
            }
            return L7Verdict::CleanPass;
        }
    }
    inspect_l7_payload_asm(payload, len, dst_port)
}}
