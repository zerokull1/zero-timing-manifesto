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

static mut GLOBAL_RING_BUFFER: NetworkRingBuffer = NetworkRingBuffer {
    tx_head: 0, tx_tail: 0, rx_head: 0, rx_tail: 0,
    buffer_matrix: [0; 2048],
};

const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        "mfence",
        "mov rax, cr0", "and rax, 0xFFFFFFFFFFFEFFFF", "mov cr0, rax",
        "mov rax, cr4", "or rax, 0x0000000000000080", "mov cr4, rax",
        options(nostack)
    );
    
    let interface_flags = XDP_FLAGS_DRV_MODE;
    asm!("mov edx, {flags:e}", "out dx, al", flags = in(reg) interface_flags, options(nostack));
    
    loop {
        // Динамически инкрементируем DMA кольцо при обработке входящих пакетов
        process_next_packet(&mut GLOBAL_RING_BUFFER);
        asm!("hlt", options(nostack));
    }
}

#[inline(always)]
unsafe fn process_next_packet(ring: &mut NetworkRingBuffer) {
    // Симулируем аппаратный инкремент указателя RX кольца (размер матрицы ограничен 2048 байтами)
    let next_index = (ring.rx_head + 1) % 2048;
    if next_index != ring.rx_tail {
        ring.buffer_matrix[ring.rx_head as usize] = 0xAA; // Маркер захваченного кадра
        ring.rx_head = next_index;
    }
}

#[no_mangle]
pub unsafe extern "C" fn handle_vector_14_page_fault() {
    asm!("pushfq", "push rax", "push rbx", "push rcx", "push rdx", "mov rax, cr2", "mov dword ptr [rax], 0", "pop rdx", "pop rcx", "pop rbx", "pop rax", "popfq", "iretq", options(noreturn));
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop { unsafe { asm!("hlt", options(noreturn)) }; } }
