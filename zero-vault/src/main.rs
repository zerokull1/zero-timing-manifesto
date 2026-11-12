#![no_std]
#![no_main]
mod base32; mod mem_guard; mod totp; mod usb_watch;
use core::arch::asm;

unsafe fn write_str(s: &[u8]) { asm!("syscall", in("rax") 1usize, in("rdi") 1usize, in("rsi") s.as_ptr(), in("rdx") s.len(), out("rcx") _, out("r11") _, options(nostack)); }
unsafe fn now_sec() -> u64 { let mut ts = [0u64; 2]; asm!("syscall", in("rax") 228usize, in("rdi") 0usize, in("rsi") ts.as_mut_ptr(), out("rcx") _, out("r11") _, options(nostack)); *ts.as_ptr() }
unsafe fn print_6d(mut c: u32) { let mut b = [b'0'; 6]; for i in (0..6).rev() { b[i] = b'0' + (c % 10) as u8; c /= 10; } write_str(&b); }

#[unsafe(naked)] #[no_mangle]
pub unsafe extern "C" fn _start() -> ! { core::arch::naked_asm!("mov rdi, rsp", "and rsp, -16", "call {e}", e = sym entry); }

pub extern "C" fn entry(sp: *const usize) -> ! {
    unsafe {
        let (argc, argv) = (*sp, sp.add(1) as *const *const u8);
        let (mut in_b, mut key_b) = ([0u8; 128], [0u8; 64]);
        mem_guard::lock_memory(in_b.as_ptr(), 128); mem_guard::lock_memory(key_b.as_ptr(), 64);
        if argc >= 3 {
            let n = usb_watch::ingest_and_shred_usb_key(*argv.add(2), &mut in_b);
            if n == 0 { write_str(b"[ERR] USB key missing\n"); usb_watch::wipe_and_exit(&mut in_b, &mut key_b); }
            let klen = base32::decode_base32(&in_b[..n], &mut key_b);
            mem_guard::wipe_secret(&mut in_b);
            write_str(b"[USB-SHRED] Ingested to mlock() RAM & wiped from USB!\n");
            loop {
                if !usb_watch::path_exists(*argv.add(1)) { write_str(b"\n[USB DETACHED] RAM Wiped!\n"); usb_watch::wipe_and_exit(&mut in_b, &mut key_b); }
                write_str(b"\r[ARMED] 2FA: "); print_6d(totp::generate_totp(&key_b[..klen], now_sec()));
                usb_watch::sleep_ms(250);
            }
        }
        let klen = base32::decode_base32(b"JBSWY3DPEHPK3PXP", &mut key_b);
        write_str(b"Demo 2FA: "); print_6d(totp::generate_totp(&key_b[..klen], now_sec())); write_str(b"\n");
        usb_watch::wipe_and_exit(&mut in_b, &mut key_b);
    }
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
