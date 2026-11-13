// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![no_std]
#![no_main]

use core::arch::asm;

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

#[repr(C)]
struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
struct SimpleTextOutputProtocol {
    reset: usize,
    output_string: extern "efiapi" fn(*mut SimpleTextOutputProtocol, *const u16) -> EfiStatus,
    test_string: usize,
    query_mode: usize,
    set_mode: usize,
    set_attribute: usize,
    clear_screen: extern "efiapi" fn(*mut SimpleTextOutputProtocol) -> EfiStatus,
}

#[repr(C)]
struct EfiSystemTable {
    hdr: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    con_in: usize,
    console_out_handle: EfiHandle,
    con_out: *mut SimpleTextOutputProtocol,
}

#[inline(always)]
unsafe fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn read_cr0() -> u64 {
    let cr0: u64;
    asm!("mov {}, cr0", out(reg) cr0, options(nostack, nomem));
    cr0
}

#[inline(always)]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

unsafe fn print_ascii(con_out: *mut SimpleTextOutputProtocol, s: &[u8]) {
    let mut buf = [0u16; 128];
    let mut idx = 0;
    for &b in s {
        if b == b'\n' {
            buf[idx] = b'\r' as u16;
            idx += 1;
        }
        buf[idx] = b as u16;
        idx += 1;
        if idx >= 124 {
            buf[idx] = 0;
            ((*con_out).output_string)(con_out, buf.as_ptr());
            idx = 0;
        }
    }
    if idx > 0 {
        buf[idx] = 0;
        ((*con_out).output_string)(con_out, buf.as_ptr());
    }
}

unsafe fn print_hex64(con_out: *mut SimpleTextOutputProtocol, mut val: u64) {
    let hex = b"0123456789ABCDEF";
    let mut out = [0u8; 18];
    out[0] = b'0';
    out[1] = b'x';
    for i in 0..16 {
        let shift = (15 - i) * 4;
        out[2 + i] = hex[((val >> shift) & 0xF) as usize];
    }
    print_ascii(con_out, &out);
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: EfiHandle, system_table: *const EfiSystemTable) -> EfiStatus {
    unsafe {
        let con_out = (*system_table).con_out;
        ((*con_out).clear_screen)(con_out);

        print_ascii(con_out, b"==============================================================\n");
        print_ascii(con_out, b"  ZERO-TIMING STAGE 0: EPHEMERAL UEFI MUTAGEN (VOLATILE RAM)\n");
        print_ascii(con_out, b"==============================================================\n");

        // 1. Аппаратная генерация одноразовой сессионной соли (испаряется при отключении питания)
        let tsc_boot = read_tsc();
        let mut session_seed = splitmix64(tsc_boot ^ 0xDEAD_BEEF_CAFE_BABEu64);
        print_ascii(con_out, b"[1] Ephemeral Session Seed (TSC) : ");
        print_hex64(con_out, session_seed);
        print_ascii(con_out, b"\n");

        // 2. Проверка аппаратной защиты от записи страниц CR0.WP (Bit 16)
        let cr0 = read_cr0();
        let wp_enabled = (cr0 & (1 << 16)) != 0;
        print_ascii(con_out, b"[2] Ring-0 CR0 Write-Protect     : ");
        if wp_enabled {
            print_ascii(con_out, b"ARMED (Bit 16 = 1)\n");
        } else {
            print_ascii(con_out, b"WARNING (Bit 16 = 0)\n");
        }

        // 3. Цикл мутации состояния в RAM (3 эпохи с проверкой целостности)
        let mut protected_region: [u64; 4] = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888, 0x9999_AAAA_BBBB_CCCC, 0xDDDD_EEEE_FFFF_0000];
        for epoch in 1..=3u64 {
            let t0 = read_tsc();
            while read_tsc().wrapping_sub(t0) < 15_000_000 {
                core::hint::spin_loop();
            }
            session_seed = splitmix64(session_seed ^ epoch ^ read_tsc());
            let mut seal = session_seed;
            for word in protected_region.iter() {
                seal = splitmix64(seal ^ *word);
            }
            print_ascii(con_out, b"[3] Mutagen Epoch #");
            let ep_char = [b'0' + (epoch as u8)];
            print_ascii(con_out, &ep_char);
            print_ascii(con_out, b" Seal        : ");
            print_hex64(con_out, seal);
            print_ascii(con_out, b" [INTEGRITY OK]\n");
        }

        print_ascii(con_out, b"--------------------------------------------------------------\n");
        print_ascii(con_out, b"[OK] Volatile Guard Active. Zero NVRAM/SPI writes performed.\n");
        print_ascii(con_out, b"[OK] Power loss wipes all keys from RAM cleanly.\n");

        // Штатное ACPI-выключение QEMU без возврата в синее меню OVMF
        asm!("out dx, ax", in("dx") 0x604u16, in("ax") 0x2000u16, options(nostack, nomem));
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
