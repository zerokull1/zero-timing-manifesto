#![no_std]
#![no_main]

mod tsc;

use core::arch::asm;
use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
use core::panic::PanicInfo;

#[repr(align(64))]
struct CacheLinePacket {
    data: [u64; 8], // Ровно 64 байта (1 кэш-линия L1)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sys_exit(1);
}

#[inline(always)]
fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!(
            "syscall",
            in("rax") 1usize, // SYS_write
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
            in("rax") 60usize, // SYS_exit
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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let packet = CacheLinePacket {
        data: [1, 2, 3, 4, 5, 6, 7, 8],
    };

    // Прогрев кэша и замер чтения выровненной кэш-линии с prefetcht0
    let (sum, cycles) = tsc::measure_cycles(|| {
        unsafe {
            _mm_prefetch(packet.data.as_ptr() as *const i8, _MM_HINT_T0);
        }
        let mut acc = 0u64;
        for i in 0..8 {
            acc = acc.wrapping_add(unsafe { core::ptr::read_volatile(&packet.data[i]) });
        }
        acc
    });

    print_str("[Zero-Timing Core] Checksum: ");
    print_u64(sum);
    print_str(" | Latency: ");
    print_u64(cycles);
    print_str(" CPU cycles\n");

    sys_exit(0);
}
