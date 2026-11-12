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


#[path = "../src/ttl_guard.rs"]
mod ttl_guard;
use ttl_guard::{GLOBAL_TTL_GUARD, TTL_VERDICT_DROP, TTL_VERDICT_TRAP};

#[no_mangle]
pub extern "C" fn zero_cisco_add_whitelist(net_be: u32, mask_be: u32) -> u32 {
    if GLOBAL_TTL_GUARD.add_whitelist_cidr(net_be, mask_be) { 1 } else { 0 }
}


#[inline(never)]
unsafe fn sync_shm_telemetry(trapped: u64, whitelisted: u64) {
    let path = b"/dev/shm/zero_ring\0";
    let mut fd: isize;
    core::arch::asm!(
        "syscall",
        in("rax") 2usize, // sys_open
        in("rdi") path.as_ptr(),
        in("rsi") 0x42usize, // O_CREAT | O_RDWR
        in("rdx") 0o666usize,
        lateout("rax") fd,
        out("rcx") _, out("r11") _,
    );
    if fd >= 0 {
        let mut buf = [0u8; 64];
        buf[0..8].copy_from_slice(&0x5A45524F52494E47u64.to_le_bytes()); // "ZERORING"
        buf[32..40].copy_from_slice(&trapped.to_le_bytes());
        buf[40..48].copy_from_slice(&whitelisted.to_le_bytes());
        let mut written: isize;
        core::arch::asm!(
            "syscall",
            in("rax") 1usize, // sys_write
            in("rdi") fd as usize,
            in("rsi") buf.as_ptr(),
            in("rdx") 64usize,
            lateout("rax") written,
            out("rcx") _, out("r11") _,
        );
        let _ = written;
        let mut close_ret: isize;
        core::arch::asm!(
            "syscall",
            in("rax") 3usize, // sys_close
            in("rdi") fd as usize,
            lateout("rax") close_ret,
            out("rcx") _, out("r11") _,
        );
        let _ = close_ret;
    }
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
    // Быстрая проверка IPv4 Whitelist и самообучающегося TTL-профиля
    let eth_type = u16::from_be_bytes([*frame_ptr.add(12), *frame_ptr.add(13)]);
    if eth_type == 0x0800 {
        let ip_ttl = *frame_ptr.add(22);
        let ip_proto = *frame_ptr.add(23);
        let frag_field = u16::from_be_bytes([*frame_ptr.add(20), *frame_ptr.add(21)]);
        let src_ip = u32::from_be_bytes([*frame_ptr.add(26), *frame_ptr.add(27), *frame_ptr.add(28), *frame_ptr.add(29)]);
        let dst_ip = u32::from_be_bytes([*frame_ptr.add(30), *frame_ptr.add(31), *frame_ptr.add(32), *frame_ptr.add(33)]);
        let tcp_flags = if ip_proto == 6 { *frame_ptr.add(47) } else { 0 };
        let ttl_v = GLOBAL_TTL_GUARD.inspect_packet_ipv4(src_ip, dst_ip, ip_ttl, frag_field, tcp_flags, frame_len.saturating_sub(54));
        let chk = GLOBAL_TTL_GUARD.total_checked.load(Ordering::Relaxed);
        if (chk & 0xFF) == 0 {
            sync_shm_telemetry(
                GLOBAL_TTL_GUARD.total_trapped.load(Ordering::Relaxed),
                GLOBAL_TTL_GUARD.total_whitelisted.load(Ordering::Relaxed),
            );
        }
        if ttl_v == TTL_VERDICT_DROP {
            DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        if ttl_v == TTL_VERDICT_TRAP {
            return 2; // DECEPTION_TRAP
        }
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

    // 2.1 Мгновенный сброс фрагментированных IPv4-пакетов (MF bit 0x2000 или FragOffset != 0)
    let frag_off = u16::from_be(core::ptr::read_unaligned(frame_ptr.add(20) as *const u16));
    if (frag_off & 0x3FFF) != 0 {
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

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
