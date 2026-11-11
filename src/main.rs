#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;

#[allow(dead_code)]
#[repr(align(64))]
pub struct NetworkRingBuffer {
    tx_head: u32, tx_tail: u32, rx_head: u32, rx_tail: u32,
    buffer_matrix: [u8; 2048],
}

const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    // 1. АППАРАТНЫЙ БАРЬЕР И ЗАХВАТ РЕГИСТРОВ УПРАВЛЕНИЯ CR0/CR4
    asm!(
        "mfence",
        // Перехват CR0: Чтение -> Сброс 16-го бита (WP) -> Запись обратно
        "mov rax, cr0",
        "and rax, 0xFFFFFFFFFFFEFFFF", 
        "mov cr0, rax",
        // Перехват CR4: Чтение -> Установка 7-го бита (PGE) -> Запись обратно
        "mov rax, cr4",
        "or rax, 0x0000000000000080",
        "mov cr4, rax",
        options(nostack)
    );
    
    let interface_flags = XDP_FLAGS_DRV_MODE;
    asm!("mov edx, {flags:e}", "out dx, al", flags = in(reg) interface_flags, options(nostack));
    loop { asm!("hlt", options(nostack)); }
}

#[no_mangle]
pub unsafe extern "C" fn handle_vector_14_page_fault() {
    asm!("pushfq", "push rax", "push rbx", "push rcx", "push rdx", "mov rax, cr2", "mov dword ptr [rax], 0", "pop rdx", "pop rcx", "pop rbx", "pop rax", "popfq", "iretq", options(noreturn));
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop { unsafe { asm!("hlt", options(noreturn)) }; } }
