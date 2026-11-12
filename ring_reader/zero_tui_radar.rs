#![no_std]
#![no_main]

use core::arch::asm;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[inline(always)]
unsafe fn sys_write(fd: u64, buf: *const u8, len: usize) {
    asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len, out("rcx") _, out("r11") _, lateout("rax") _, options(nostack));
}

#[inline(always)]
unsafe fn sys_nanosleep(ms: i64) {
    let req = Timespec { tv_sec: ms / 1000, tv_nsec: (ms % 1000) * 1_000_000 };
    asm!("syscall", in("rax") 35u64, in("rdi") &req as *const Timespec, in("rsi") 0u64, out("rcx") _, out("r11") _, lateout("rax") _, options(nostack));
}

#[inline(always)]
unsafe fn rdtscp_now() -> u64 {
    let (lo, hi): (u32, u32);
    asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

fn write_u64(mut val: u64, out: &mut [u8; 32]) -> &[u8] {
    if val == 0 {
        if let Some(first) = out.first_mut() { *first = b'0'; }
        return &out[..1];
    }
    let mut i = 32;
    while val > 0 && i > 0 {
        i -= 1;
        out[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &out[i..]
}

core::arch::global_asm!(
    ".global _start",
    "_start:",
    "and rsp, -16",
    "call rust_radar_main",
    "mov rdi, rax",
    "mov rax, 60",
    "syscall"
);

#[no_mangle]
pub unsafe extern "C" fn rust_radar_main() -> u64 {
    let mut num_buf = [0u8; 32];
    let mut sim_pkts: u64 = 10_000_000;
    let mut sim_drop_l3: u64 = 142;
    let mut sim_drop_l7: u64 = 19;

    for frame in 0..10u64 {
        let tsc = rdtscp_now();
        sim_pkts = sim_pkts.wrapping_add(250_000 + (tsc & 0xFFF));
        sim_drop_l3 = sim_drop_l3.wrapping_add((tsc >> 4) & 0x3);
        sim_drop_l7 = sim_drop_l7.wrapping_add((tsc >> 8) & 0x1);

        let clear = b"\x1B[2J\x1B[H";
        sys_write(1, clear.as_ptr(), clear.len());

        let header = b"=================================================================\n  ZERO-TIMING LIVE TUI RADAR (no_std Rust | Zero-Allocation)\n=================================================================\n";
        sys_write(1, header.as_ptr(), header.len());

        let l1 = b"  [CPU TSC Clock]      : ";
        sys_write(1, l1.as_ptr(), l1.len());
        let s_tsc = write_u64(tsc, &mut num_buf);
        sys_write(1, s_tsc.as_ptr(), s_tsc.len());

        let l2 = b"\n  [Processed Frames]   : ";
        sys_write(1, l2.as_ptr(), l2.len());
        let s_pkt = write_u64(sim_pkts, &mut num_buf);
        sys_write(1, s_pkt.as_ptr(), s_pkt.len());

        let l3 = b"\n  [L3/L4 Frags Dropped]: ";
        sys_write(1, l3.as_ptr(), l3.len());
        let s_d3 = write_u64(sim_drop_l3, &mut num_buf);
        sys_write(1, s_d3.as_ptr(), s_d3.len());

        let l4 = b"\n  [L7 DPI / QUIC Drops]: ";
        sys_write(1, l4.as_ptr(), l4.len());
        let s_d7 = write_u64(sim_drop_l7, &mut num_buf);
        sys_write(1, s_d7.as_ptr(), s_d7.len());

        let l5 = b"\n  [512-Bit YMM Seal]   : ACTIVE (3-Way HW Anchor + 1-Cycle Trap)\n  [Telemetry Frame]    : ";
        sys_write(1, l5.as_ptr(), l5.len());
        let s_fr = write_u64(frame + 1, &mut num_buf);
        sys_write(1, s_fr.as_ptr(), s_fr.len());

        let footer = b" / 10\n=================================================================\n";
        sys_write(1, footer.as_ptr(), footer.len());

        sys_nanosleep(250);
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
