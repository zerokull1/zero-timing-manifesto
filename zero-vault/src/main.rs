#![no_std]
#![no_main]
mod base32; mod cpu_reg_vault; mod mem_guard; mod totp; mod usb_watch;
use core::arch::asm;

unsafe fn write_str(s: &[u8]) { asm!("syscall", in("rax") 1usize, in("rdi") 1usize, in("rsi") s.as_ptr(), in("rdx") s.len(), out("rcx") _, out("r11") _, options(nostack)); }
unsafe fn now_sec() -> u64 { let mut ts = [0u64; 2]; asm!("syscall", in("rax") 228usize, in("rdi") 0usize, in("rsi") ts.as_mut_ptr(), out("rcx") _, out("r11") _, options(nostack)); *ts.as_ptr() }
unsafe fn print_6d(mut c: u32) { let mut b = [b'0'; 6]; for i in (0..6).rev() { b[i] = b'0' + (c % 10) as u8; c /= 10; } write_str(&b); }

#[unsafe(naked)] #[no_mangle]
pub unsafe extern "C" fn _start() -> ! { core::arch::naked_asm!("mov rdi, rsp", "and rsp, -16", "call {e}", e = sym entry); }

pub extern "C" fn entry(sp: *const usize) -> ! {
    unsafe {
        let (argc, argv) = (*sp, sp.add(1) as *const *const u8);
        let (mut in_b, mut ddr_key) = ([0u8; 128], [0u8; 32]);
        mem_guard::lock_memory(in_b.as_ptr(), 128); mem_guard::lock_memory(ddr_key.as_ptr(), 32);

        let klen = if argc >= 3 {
            let n = usb_watch::ingest_and_shred_usb_key(*argv.add(2), &mut in_b);
            if n == 0 { write_str(b"[ERR] USB key missing\n"); usb_watch::wipe_and_exit(&mut in_b, &mut ddr_key); }
            let l = base32::decode_base32(&in_b[..n], &mut ddr_key);
            mem_guard::wipe_secret(&mut in_b);
            l
        } else {
            base32::decode_base32(b"JBSWY3DPEHPK3PXP", &mut ddr_key)
        };

        // Запечатываем ключ в кристалл CPU (YMM15) и полностью затираем DDR (Cold-Boot Proof)
        cpu_reg_vault::seal_key_in_ymm15(&mut ddr_key);

        if argc >= 3 {
            write_str(b"[COLD-BOOT SHIELD] Key sealed in CPU YMM15 register (DDR = 0x00)!\n");
            loop {
                if !usb_watch::path_exists(*argv.add(1)) {
                    cpu_reg_vault::wipe_ymm15();
                    write_str(b"\n[USB DETACHED] CPU YMM15 & RAM Wiped!\n");
                    usb_watch::wipe_and_exit(&mut in_b, &mut ddr_key);
                }
                cpu_reg_vault::read_key_from_ymm15(&mut ddr_key);
                let code = totp::generate_totp(&ddr_key[..klen], now_sec());
                mem_guard::wipe_secret(&mut ddr_key);
                write_str(b"\r[ARMED YMM15] 2FA: "); print_6d(code);
                usb_watch::sleep_ms(250);
            }
        }

        cpu_reg_vault::read_key_from_ymm15(&mut ddr_key);
        let code = totp::generate_totp(&ddr_key[..klen], now_sec());
        mem_guard::wipe_secret(&mut ddr_key);
        cpu_reg_vault::wipe_ymm15();
        write_str(b"[YMM15 TRESOR-MODE] 2FA Token: "); print_6d(code); write_str(b" | DDR & YMM15 Wiped [OK]\n");
        usb_watch::wipe_and_exit(&mut in_b, &mut ddr_key);
    }
}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
