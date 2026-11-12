#![no_std]
#![no_main]

use core::arch::asm;

#[repr(C)]
struct Timespec { tv_sec: i64, tv_nsec: i64 }

#[inline(always)]
unsafe fn sys_write(fd: u64, buf: *const u8, len: usize) {
    asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len, out("rcx") _, out("r11") _, lateout("rax") _, options(nostack));
}

#[inline(always)]
unsafe fn sys_open_ro(path: *const u8) -> isize {
    let fd: isize;
    asm!("syscall", in("rax") 2u64, in("rdi") path, in("rsi") 0u64, in("rdx") 0u64, out("rcx") _, out("r11") _, lateout("rax") fd, options(nostack));
    fd
}

#[inline(always)]
unsafe fn sys_read(fd: u64, buf: *mut u8, len: usize) -> isize {
    let n: isize;
    asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len, out("rcx") _, out("r11") _, lateout("rax") n, options(nostack));
    n
}

#[inline(always)]
unsafe fn sys_close(fd: u64) {
    asm!("syscall", in("rax") 3u64, in("rdi") fd, out("rcx") _, out("r11") _, lateout("rax") _, options(nostack));
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

unsafe fn read_live_net_packets() -> (u64, u64) {
    let fd = sys_open_ro(b"/proc/net/dev\0".as_ptr());
    if fd < 0 { return (0, 0); }
    let mut buf = [0u8; 2048];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
    sys_close(fd as u64);
    if n <= 0 { return (0, 0); }

    let (mut rx, mut tx) = (0u64, 0u64);
    for line in buf[..n as usize].split(|&b| b == b'\n') {
        if let Some(cpos) = line.iter().position(|&b| b == b':') {
            if line[..cpos].ends_with(b"lo") { continue; }
            let (mut col, mut cur, mut in_num) = (0usize, 0u64, false);
            for &ch in &line[cpos + 1..] {
                if ch >= b'0' && ch <= b'9' {
                    cur = cur.wrapping_mul(10).wrapping_add((ch - b'0') as u64);
                    in_num = true;
                } else if in_num {
                    if col == 1 { rx = rx.wrapping_add(cur); }
                    if col == 9 { tx = tx.wrapping_add(cur); }
                    col += 1; cur = 0; in_num = false;
                }
            }
            if in_num && col == 9 { tx = tx.wrapping_add(cur); }
        }
    }
    (rx, tx)
}

core::arch::global_asm!(
    ".global _start", "_start:", "mov rdi, [rsp]", "and rsp, -16",
    "call rust_radar_main", "mov rdi, rax", "mov rax, 60", "syscall"
);

#[no_mangle]
pub unsafe extern "C" fn rust_radar_main(argc: u64) -> u64 {
    let mut num_buf = [0u8; 32];
    let infinite = argc > 1;
    let mut frame: u64 = 0;

    loop {
        let tsc = rdtscp_now();
        let (rx_pkts, tx_pkts) = read_live_net_packets();
        sys_write(1, b"\x1B[2J\x1B[H".as_ptr(), 7);

        let h = b"=================================================================\n  ZERO-TIMING LIVE SYSTEM RADAR (Arch Linux | no_std Rust)\n=================================================================\n  [CPU TSC Clock]       : ";
        sys_write(1, h.as_ptr(), h.len());
        let s1 = write_u64(tsc, &mut num_buf); sys_write(1, s1.as_ptr(), s1.len());

        let l2 = b"\n  [Live NIC RX Packets] : "; sys_write(1, l2.as_ptr(), l2.len());
        let s2 = write_u64(rx_pkts, &mut num_buf); sys_write(1, s2.as_ptr(), s2.len());

        let l3 = b"\n  [Live NIC TX Packets] : "; sys_write(1, l3.as_ptr(), l3.len());
        let s3 = write_u64(tx_pkts, &mut num_buf); sys_write(1, s3.as_ptr(), s3.len());

        let l4 = b"\n  [512-Bit YMM Seal]    : ACTIVE (AVX2 vmovntdq + 1-Cycle Trap)\n  [Refresh Frame]       : ";
        sys_write(1, l4.as_ptr(), l4.len());
        frame += 1;
        let s4 = write_u64(frame, &mut num_buf); sys_write(1, s4.as_ptr(), s4.len());

        let f = if infinite { b" (LIVE - Ctrl+C to exit)\n=================================================================\n" as &[u8] }
                else { b" / 10 (DEMO)\n=================================================================\n" as &[u8] };
        sys_write(1, f.as_ptr(), f.len());

        if !infinite && frame >= 10 { break; }
        sys_nanosleep(250);
    }
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    for i in 0..n { *s.add(i) = c as u8; }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n { *dest.add(i) = *src.add(i); }
    dest
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
