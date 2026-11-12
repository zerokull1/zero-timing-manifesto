use core::arch::asm;
use core::ptr::write_volatile;

#[inline(always)]
pub unsafe fn lock_memory(ptr: *const u8, len: usize) -> isize {
    let ret: isize;
    asm!("syscall", in("rax") 149usize, in("rdi") ptr, in("rsi") len, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}

#[inline(never)]
pub unsafe fn wipe_secret(buf: &mut [u8]) {
    for b in buf.iter_mut() { write_volatile(b, 0); }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[no_mangle] pub unsafe extern "C" fn memcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 { for i in 0..n { *d.add(i) = *s.add(i); } d }
#[no_mangle] pub unsafe extern "C" fn memset(d: *mut u8, c: i32, n: usize) -> *mut u8 { for i in 0..n { *d.add(i) = c as u8; } d }
#[no_mangle] pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 { for i in 0..n { if *a.add(i) != *b.add(i) { return *a.add(i) as i32 - *b.add(i) as i32; } } 0 }
#[no_mangle] pub extern "C" fn rust_eh_personality() {}
