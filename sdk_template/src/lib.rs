#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop {} }

#[no_mangle]
#[target_feature(enable = "avx")]
pub unsafe extern "C" fn asm_stream_write_32(dst_aligned32: *mut u8, src_aligned32: *const u8) {
    unsafe {
        asm!(
            "vmovdqu ymm0, [{src}]",
            "vmovntdq [{dst}], ymm0",
            "sfence",
            src = in(reg) src_aligned32,
            dst = in(reg) dst_aligned32,
            out("ymm0") _,
            options(nostack)
        );
    }
}

#[no_mangle]
#[target_feature(enable = "rdrand")]
pub unsafe extern "C" fn asm_hw_entropy_u64() -> u64 {
    let mut val: u64;
    unsafe {
        asm!(
            "2:",
            "rdrand {val}",
            "jnc 2b",
            val = out(reg) val,
            options(nomem, nostack)
        );
    }
    val
}

#[no_mangle]
pub unsafe extern "C" fn rust_core_process(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len == 0 { return 0; }
    let slice = unsafe { core::slice::from_raw_parts(buf, len) };
    let mut hash: u32 = 0x811c9dc5;
    for &b in slice {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
