#![no_std]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static TOTAL_PKTS: AtomicU64 = AtomicU64::new(0);
static DROPPED_L3_L4: AtomicU64 = AtomicU64::new(0);
static DROPPED_L7: AtomicU64 = AtomicU64::new(0);
static LAST_CYCLES: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
pub struct ZeroCiscoStats {
    pub total_inspected: u64,
    pub dropped_l3_l4: u64,
    pub dropped_l7: u64,
    pub last_latency_cycles: u64,
}

#[inline(always)]
unsafe fn rdtsc_start() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn rdtscp_end() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[no_mangle]
pub extern "C" fn zero_cisco_init() {
    TOTAL_PKTS.store(0, Ordering::Release);
    DROPPED_L3_L4.store(0, Ordering::Release);
    DROPPED_L7.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn zero_cisco_inspect_frame(frame_ptr: *const u8, frame_len: usize) -> u32 {
    if frame_ptr.is_null() || frame_len < 54 {
        return 0;
    }

    let t0 = rdtsc_start();
    TOTAL_PKTS.fetch_add(1, Ordering::Relaxed);

    // 1. Проверка EtherType == IPv4 (0x0800)
    let eth_proto = u16::from_be(core::ptr::read_unaligned(frame_ptr.add(12) as *const u16));
    if eth_proto != 0x0800 {
        return 0;
    }

    // 2. Проверка IPv4 Protocol == TCP (6) и длины заголовка
    let ver_ihl = *frame_ptr.add(14);
    let ip_hdr_len = ((ver_ihl & 0x0F) as usize) * 4;
    if ip_hdr_len < 20 || frame_len < 14 + ip_hdr_len + 20 {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        return 1;
    }

    let proto = *frame_ptr.add(23);
    if proto != 6 {
        return 0;
    }

    // 3. L3/L4 Аппаратная блокада TCP Null-сегментов (флаги == 0x00)
    let tcp_off = 14 + ip_hdr_len;
    let tcp_flags = *frame_ptr.add(tcp_off + 13);
    if tcp_flags == 0x00 {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        let t1 = rdtscp_end();
        LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
        return 1;
    }

    // 4. Безветвящийся x86_64 ASM L7 DPI (HTTP Smuggling + TLS 1.3 Record Anomaly)
    let tcp_hdr_len = (((*frame_ptr.add(tcp_off + 12)) >> 4) as usize) * 4;
    let payload_off = tcp_off + tcp_hdr_len;
    if frame_len >= payload_off + 16 {
        let p = frame_ptr.add(payload_off);
        let q0 = core::ptr::read_unaligned(p as *const u64);
        let q1 = core::ptr::read_unaligned(p.add(8) as *const u64);

        let mut verdict: u64 = 0;
        let smuggle_sig: u64 = 0x2020_2F20_5453_4F50; // "POST /  "
        let tls_hdr: u64 = q0 & 0x0000_0000_00FF_FFFF;
        let tls_sig: u64 = 0x0000_0000_0003_0316;     // TLS 1.2/1.3 Handshake
        let rec_len: u16 = u16::from_be(((q0 >> 24) & 0xFFFF) as u16);

        asm!(
            "cmp {q0}, {smug}",
            "mov {tmp}, 2",
            "cmove {verd}, {tmp}",
            "cmp {tls_h}, {tls_s}",
            "jne 2f",
            "cmp {rlen:x}, 16384",
            "mov {tmp}, 3",
            "cmova {verd}, {tmp}",
            "2:",
            q0 = in(reg) q0,
            smug = in(reg) smuggle_sig,
            tls_h = in(reg) tls_hdr,
            tls_s = in(reg) tls_sig,
            rlen = in(reg) rec_len,
            tmp = out(reg) _,
            verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );

        let _ = q1;
        if verdict != 0 {
            DROPPED_L7.fetch_add(1, Ordering::Relaxed);
            let t1 = rdtscp_end();
            LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
            return verdict as u32;
        }
    }

    let t1 = rdtscp_end();
    LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
    0
}

#[no_mangle]
pub unsafe extern "C" fn zero_cisco_get_stats(out_stats: *mut ZeroCiscoStats) {
    if !out_stats.is_null() {
        (*out_stats).total_inspected = TOTAL_PKTS.load(Ordering::Acquire);
        (*out_stats).dropped_l3_l4 = DROPPED_L3_L4.load(Ordering::Acquire);
        (*out_stats).dropped_l7 = DROPPED_L7.load(Ordering::Acquire);
        (*out_stats).last_latency_cycles = LAST_CYCLES.load(Ordering::Acquire);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
