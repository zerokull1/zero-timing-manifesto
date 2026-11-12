use core::arch::asm;
use crate::mem_guard::wipe_secret;

pub unsafe fn path_exists(p: *const u8) -> bool {
    let r: isize;
    asm!("syscall", in("rax") 269usize, in("rdi") -100isize as usize, in("rsi") p, in("rdx") 0usize, in("r10") 0usize, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    r == 0
}

pub unsafe fn ingest_and_shred_usb_key(p: *const u8, out: &mut [u8]) -> usize {
    let fd: isize;
    asm!("syscall", in("rax") 257usize, in("rdi") -100isize as usize, in("rsi") p, in("rdx") 2usize, in("r10") 0usize, lateout("rax") fd, out("rcx") _, out("r11") _, options(nostack));
    if fd < 0 { return 0; }
    let n: isize;
    asm!("syscall", in("rax") 0usize, in("rdi") fd as usize, in("rsi") out.as_mut_ptr(), in("rdx") out.len(), lateout("rax") n, out("rcx") _, out("r11") _, options(nostack));
    let z = [0u8; 128];
    asm!("syscall", in("rax") 8usize, in("rdi") fd as usize, in("rsi") 0usize, in("rdx") 0usize, out("rcx") _, out("r11") _, options(nostack));
    asm!("syscall", in("rax") 1usize, in("rdi") fd as usize, in("rsi") z.as_ptr(), in("rdx") 128usize, out("rcx") _, out("r11") _, options(nostack));
    asm!("syscall", in("rax") 3usize, in("rdi") fd as usize, out("rcx") _, out("r11") _, options(nostack));
    asm!("syscall", in("rax") 263usize, in("rdi") -100isize as usize, in("rsi") p, in("rdx") 0usize, out("rcx") _, out("r11") _, options(nostack));
    if n > 0 { n as usize } else { 0 }
}

pub unsafe fn sleep_ms(ms: u64) {
    let req = [ms / 1000, (ms % 1000) * 1_000_000];
    asm!("syscall", in("rax") 35usize, in("rdi") req.as_ptr(), in("rsi") 0usize, out("rcx") _, out("r11") _, options(nostack));
}

pub unsafe fn wipe_and_exit(a: &mut [u8], b: &mut [u8]) -> ! {
    wipe_secret(a); wipe_secret(b);
    asm!("syscall", in("rax") 60usize, in("rdi") 0usize, options(noreturn));
}
