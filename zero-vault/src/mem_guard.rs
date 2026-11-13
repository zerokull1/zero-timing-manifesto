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

#[no_mangle] pub unsafe extern "C" fn memcpy(d: *mut core::ffi::c_void, s: *const core::ffi::c_void, n: usize) -> *mut core::ffi::c_void { for i in 0..n { core::ptr::write_volatile((d as *mut u8).add(i), core::ptr::read_volatile((s as *const u8).add(i))); } d }
#[no_mangle] pub unsafe extern "C" fn memset(d: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void { for i in 0..n { core::ptr::write_volatile((d as *mut u8).add(i), c as u8); } d }
#[no_mangle] pub unsafe extern "C" fn memcmp(a: *const core::ffi::c_void, b: *const core::ffi::c_void, n: usize) -> i32 { for i in 0..n { if *(a as *const u8).add(i) != *(b as *const u8).add(i) { return *(a as *const u8).add(i) as i32 - *(b as *const u8).add(i) as i32; } } 0 }
#[no_mangle] pub extern "C" fn rust_eh_personality() {}
