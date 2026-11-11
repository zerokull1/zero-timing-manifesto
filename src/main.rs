#![no_std]
#![no_main]

mod tsc;
mod core_engine;

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sys_exit(1);
}

#[inline(always)]
fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 1usize, in("rdi") fd, in("rsi") buf, in("rdx") len, out("rcx") _, out("r11") _, options(nostack));
    }
}

#[inline(always)]
fn sys_openat(dfd: isize, path: *const u8, flags: usize, mode: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") 257usize, in("rdi") dfd, in("rsi") path, in("rdx") flags, in("r10") mode, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
fn sys_ftruncate(fd: isize, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 77usize, in("rdi") fd, in("rsi") len, out("rcx") _, out("r11") _, options(nostack));
    }
}

#[inline(always)]
fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, offset: usize) -> *mut u8 {
    let ret: *mut u8;
    unsafe {
        asm!("syscall", in("rax") 9usize, in("rdi") addr, in("rsi") len, in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") offset, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60usize, in("rdi") code, options(noreturn, nostack));
    }
}

fn print_str(s: &str) { sys_write(1, s.as_ptr(), s.len()); }

fn print_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if n == 0 { print_str("0"); return; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    sys_write(1, buf[i..].as_ptr(), 20 - i);
}

fn print_hex8(val: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let buf = [b'0', b'x', HEX[((val >> 4) & 0xF) as usize], HEX[(val & 0xF) as usize]];
    sys_write(1, buf.as_ptr(), 4);
}

#[no_mangle]
pub extern "C" fn main_entry() -> ! {
    let (anomaly_cycles, clean_cycles, mask, fixed_flags) =
        core_engine::simulate_shield_rack_benchmark();

    print_str("[Rack-Scale Shield + GPU IAT Offload]\n");
    print_str("  1. Phase 2/3 Bypass Blocked: "); print_u64(anomaly_cycles); print_str(" CPU cycles\n");
    print_str("  2. Phase 1 Clean Fast-Path:  "); print_u64(clean_cycles); print_str(" CPU cycles\n");
    print_str("  3. Active Shield Mask: "); print_hex8(mask);
    print_str(" | TCP Flags: "); print_hex8(fixed_flags); print_str("\n");

    // Открываем /dev/shm/zero_shield_ring (O_RDWR | O_CREAT = 0x42, mode 0666)
    let shm_path = b"/dev/shm/zero_shield_ring\0";
    let fd = sys_openat(-100, shm_path.as_ptr(), 0x42, 0o666);
    if fd >= 0 {
        sys_ftruncate(fd, 4096);
        // PROT_READ | PROT_WRITE = 3, MAP_SHARED = 1
        let shm_ptr = sys_mmap(0, 4096, 3, 1, fd, 0);
        if (shm_ptr as isize) > 0 {
            let ring_ptr = shm_ptr as *mut u64;
            let mut base_tsc = tsc::rdtsc_start();
            let mut i = 0usize;
            while i < 256 {
                // Внедряем 4 реальных аномальных скачка IAT для проверки GPU-фильтра
                let step = if i == 15 || i == 77 || i == 140 || i == 220 { 12000 } else { 65 };
                base_tsc += step;
                unsafe {
                    asm!("movnti [{dst}], {val}", dst = in(reg) ring_ptr.add(i), val = in(reg) base_tsc, options(nostack));
                }
                i += 1;
            }
            unsafe { asm!("sfence", options(nostack)); }
            print_str("  4. Shared DDR Ring (/dev/shm/zero_shield_ring) populated via movnti!\n");
        }
    }

    sys_exit(0);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("and rsp, -16", "call main_entry");
}
