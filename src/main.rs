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
            in("rax") 1usize,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
}

#[inline(always)]
fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60usize,
            in("rdi") code,
            options(noreturn, nostack)
        );
    }
}

fn print_str(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn print_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if n == 0 {
        print_str("0");
        return;
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    sys_write(1, buf[i..].as_ptr(), 20 - i);
}

fn print_hex32(val: u32) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8 {
        let nibble = ((val >> ((7 - i) * 4)) & 0xF) as usize;
        buf[2 + i] = HEX[nibble];
    }
    sys_write(1, buf.as_ptr(), 10);
}

#[no_mangle]
pub extern "C" fn main_entry() -> ! {
    let (trap_cycles, clean_cycles, offloaded_sig, nvme_db) =
        core_engine::simulate_ddr_trap_benchmark();

    print_str("[DDR Trap Simulation]\n");
    print_str("  1. Attack Blocked (movnti + NVMe Doorbell): ");
    print_u64(trap_cycles);
    print_str(" CPU cycles\n");

    print_str("  2. Clean Packet   (clflush + NIC Doorbell): ");
    print_u64(clean_cycles);
    print_str(" CPU cycles\n");

    print_str("  3. NVMe DMA Slot Signature: ");
    print_hex32(offloaded_sig);
    print_str(" | NVMe Doorbell Tail: ");
    print_u64(nvme_db as u64);
    print_str("\n");

    sys_exit(0);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "call main_entry"
    );
}
