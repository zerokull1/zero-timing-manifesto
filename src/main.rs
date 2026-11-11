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
        asm!(
            "syscall",
            in("rax") 1usize, in("rdi") fd, in("rsi") buf, in("rdx") len,
            out("rcx") _, out("r11") _, options(nostack)
        );
    }
}

#[inline(always)]
fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60usize, in("rdi") code, options(noreturn, nostack));
    }
}

fn print_str(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

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
    print_str("  1. Phase 2/3 Bypass Blocked (TTL+ACK Norm + NVMe SIEM + GPU IAT): ");
    print_u64(anomaly_cycles);
    print_str(" CPU cycles\n");

    print_str("  2. Phase 1 Clean Fast-Path  (L3/L4 Pass + GPU IAT Doorbell):     ");
    print_u64(clean_cycles);
    print_str(" CPU cycles\n");

    print_str("  3. Active Shield Mask: ");
    print_hex8(mask);
    print_str(" | Normalized TCP Flags (ACK): ");
    print_hex8(fixed_flags);
    print_str("\n");

    sys_exit(0);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("and rsp, -16", "call main_entry");
}
