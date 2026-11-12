#![no_std]
#![no_main]

use core::arch::asm;

type EfiStatus = usize;
type EfiHandle = *mut core::ffi::c_void;

#[repr(C)]
pub struct EfiTableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
pub struct EfiBootServices {
    hdr: EfiTableHeader,
    raise_tpl: usize,
    restore_tpl: usize,
    allocate_pages: usize,
    free_pages: usize,
    get_memory_map: extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut u8,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    allocate_pool: usize,
    free_pool: usize,
    create_event: usize,
    set_timer: usize,
    wait_for_event: usize,
    signal_event: usize,
    close_event: usize,
    check_event: usize,
    install_protocol_interface: usize,
    reinstall_protocol_interface: usize,
    uninstall_protocol_interface: usize,
    handle_protocol: usize,
    reserved: usize,
    register_protocol_notify: usize,
    locate_handle: usize,
    locate_device_path: usize,
    install_configuration_table: usize,
    load_image: usize,
    start_image: usize,
    exit: usize,
    unload_image: usize,
    exit_boot_services: extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> EfiStatus,
}

#[repr(C)]
pub struct EfiSystemTable {
    hdr: EfiTableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: EfiHandle,
    con_in: usize,
    console_out_handle: EfiHandle,
    con_out: usize,
    standard_error_handle: EfiHandle,
    std_err: usize,
    runtime_services: usize,
    boot_services: *mut EfiBootServices,
}

// Прямая запись в аппаратный порт COM1 (0x3F8) — работает в голом Ring 0 без BIOS и без ОС!
#[inline(always)]
unsafe fn serial_init() {
    let port: u16 = 0x3F8;
    outb(port + 1, 0x00);
    outb(port + 3, 0x80);
    outb(port + 0, 0x03);
    outb(port + 1, 0x00);
    outb(port + 3, 0x03);
    outb(port + 2, 0xC7);
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", in("dx") port, out("al") val, options(nostack, nomem));
    val
}

unsafe fn serial_write_bytes(s: &[u8]) {
    for &b in s {
        while (inb(0x3F8 + 5) & 0x20) == 0 {
            core::hint::spin_loop();
        }
        outb(0x3F8, b);
    }
}

unsafe fn serial_write_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    if n == 0 {
        serial_write_bytes(b"0");
        return;
    }
    let mut i = 20;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    serial_write_bytes(&buf[i..]);
}

#[inline(always)]
unsafe fn rdtscp_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nostack, nomem));
    ((hi as u64) << 32) | (lo as u64)
}

// Безветвящийся L7 + TTL Shield в голом Ring 0
#[inline(always)]
fn ring0_inspect_packet(ttl: u8, expected_ttl: u8, payload_magic: u64) -> u64 {
    let ttl_diff = (ttl as i32 - expected_ttl as i32).unsigned_abs();
    let ttl_bad = if ttl_diff > 5 { 1u64 } else { 0u64 };
    let bad_sig = if payload_magic == 0x5A45524F_44524F50 { 1u64 } else { 0u64 };
    ttl_bad | bad_sig
}

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: EfiHandle, system_table: *const EfiSystemTable) -> EfiStatus {
    unsafe {
        serial_init();
        serial_write_bytes(b"\r\n[STAGE-0] Acquiring UEFI Memory Map...\r\n");

        let bs = (*system_table).boot_services;
        let mut mmap_buf = [0u8; 32768];
        let mut mmap_size = mmap_buf.len();
        let mut map_key: usize = 0;
        let mut desc_size: usize = 0;
        let mut desc_ver: u32 = 0;

        // Получаем актуальный MapKey и вызываем ExitBootServices()
        let status = ((*bs).get_memory_map)(
            &mut mmap_size,
            mmap_buf.as_mut_ptr(),
            &mut map_key,
            &mut desc_size,
            &mut desc_ver,
        );
        if status != 0 {
            serial_write_bytes(b"[ERR] GetMemoryMap failed\r\n");
            return status;
        }

        let exit_status = ((*bs).exit_boot_services)(image_handle, map_key);
        if exit_status != 0 {
            serial_write_bytes(b"[ERR] ExitBootServices failed\r\n");
            return exit_status;
        }

        // ТОЧКА НЕВОЗВРАТА: Прошивка UEFI отключена! Мы в чистом Ring 0 без ОС!
        asm!("cli", options(nostack, nomem));

        serial_write_bytes(b"==============================================================\r\n");
        serial_write_bytes(b"  ZERO-TIMING UNIKERNEL: BARE-METAL RING 0 ACTIVE (NO OS!)\r\n");
        serial_write_bytes(b"==============================================================\r\n");
        serial_write_bytes(b"[OK] ExitBootServices() succeeded! Firmware drivers terminated.\r\n");
        serial_write_bytes(b"[OK] Interrupts masked (cli). Pure Polling Mode engaged.\r\n");

        // Боевой прогон 1 000 000 пакетов прямо в голом Ring 0
        let batch = 1_000_000u64;
        let mut dropped = 0u64;
        let t0 = rdtscp_serialized();
        for i in 0..batch {
            let idx = core::hint::black_box(i);
            let ttl = if (idx & 7) == 0 { 41 } else { 64 };
            let magic = if (idx & 15) == 0 { 0x5A45524F_44524F50 } else { 0x11223344_55667788 };
            dropped += core::hint::black_box(ring0_inspect_packet(ttl, 64, magic));
        }
        let t1 = rdtscp_serialized();
        let cycles_per_pkt = (t1.wrapping_sub(t0)) / batch;

        serial_write_bytes(b"[BENCH] 1,000,000 frames inspected in Ring 0\r\n");
        serial_write_bytes(b"[BENCH] Threats dropped (TTL + L7) : ");
        serial_write_u64(dropped);
        serial_write_bytes(b"\r\n[BENCH] Average CPU cycles / frame   : ");
        serial_write_u64(cycles_per_pkt);
        serial_write_bytes(b" cycles\r\n");
        serial_write_bytes(b"==============================================================\r\n");

        // Штатный сброс через порт 0x64 (с флагом QEMU -no-reboot мгновенно закрывает VM)
        outb(0x64, 0xFE);
        loop {
            asm!("cli; hlt", options(nostack, nomem));
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
