#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;

const MAX_SERVER_CORES: usize = 128;
const PCIE_NIC_BAR0_BASE: u64 = 0xFE000000; 
const NIC_REG_RX_DOORBELL: u64 = 0x1008;

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(align(4096))] // Каждая структура весит ровно 1 страницу памяти (4096 байт)
pub struct CoreStorage {
    tx_head: u32,
    tx_tail: u32,
    rx_head: u32,
    rx_tail: u32,
    buffer_matrix: [u8; 1024],
    ddr_trap_pad: [u8; 3056], // Ювелирно подогнанный падинг: 16+1024+3056 = 4096 байт
}

static mut SERVER_CORE_MATRIX: [CoreStorage; MAX_SERVER_CORES] = {
    let mut i = 0;
    let mut matrix = [CoreStorage {
        tx_head: 0, tx_tail: 0, rx_head: 0, rx_tail: 0,
        buffer_matrix: [0; 1024],
        ddr_trap_pad: [0; 3056],
    }; MAX_SERVER_CORES];
    
    while i < MAX_SERVER_CORES {
        matrix[i] = CoreStorage {
            tx_head: 0, tx_tail: 0, rx_head: 0, rx_tail: 0,
            buffer_matrix: [0; 1024],
            ddr_trap_pad: [0; 3056],
        };
        i += 1;
    }
    matrix
};

const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        "cli",
        "mfence",
        "mov rax, cr0", "and rax, 0xFFFFFFFFFFFEFFFF", "mov cr0, rax",
        "mov rax, cr4", "or rax, 0x0000000000000080", "mov cr4, rax",
        options(nostack)
    );

    asm!(
        "mov eax, 0x80000004", 
        "mov dx, 0xCF8",
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        "or eax, 0x0006",     
        "out dx, eax",
        options(nostack)
    );

    let interface_flags = XDP_FLAGS_DRV_MODE;
    asm!("mov edx, {flags:e}", "out dx, al", flags = in(reg) interface_flags, options(nostack));

    // Фиксируем базовый физический адрес нашей матрицы в памяти
    let matrix_base_ptr = &raw mut SERVER_CORE_MATRIX;

    loop {
        let mut core_id: u32;
        let mut _tmp_rbx: u64;
        let mut target_core_storage_ptr: *mut CoreStorage;
        
        asm!(
            "mov {tmp}, rbx",
            "mov eax, 1",
            "cpuid",
            "shr ebx, 24",
            "mov {id:e}, ebx",
            "mov rbx, {tmp}",
            id = out(reg) core_id,
            tmp = out(reg) _tmp_rbx,
            out("eax") _, out("ecx") _, out("edx") _,
            options(nostack)
        );

        // БЕЗНАГРУЗОЧНАЯ DDR-ЛОКАЛИЗАЦИЯ: Бинарный сдвиг вместо MSR-регистров
        asm!(
            "mov rax, {id}",
            "and rax, 0x7F",        // Ограничиваем индекс маской до 127 (MAX_SERVER_CORES)
            "shl rax, 12",          // Умножаем APIC ID на 4096 (размер страницы) за 1 такт!
            "add rax, {base}",      // Добавляем к базовому адресу матрицы
            "mov {out_ptr}, rax",   // Получаем готовый прямой указатель на память текущего ядра
            id = in(reg) core_id,
            base = in(reg) matrix_base_ptr,
            out_ptr = out(reg) target_core_storage_ptr,
            out("rax") _
        );

        let next_core_index = ((core_id as usize) + 1) % MAX_SERVER_CORES;
        let next_storage_ptr = &raw mut SERVER_CORE_MATRIX[next_core_index];
        asm!(
            "prefetcht0 [{ptr}]",
            ptr = in(reg) next_storage_ptr,
            options(nostack, nomem)
        );
        
        asm!("lfence", options(nostack, nomem));
        
        process_server_packet(target_core_storage_ptr);
        asm!("hlt", options(nostack));
    }
}

#[inline(always)]
unsafe fn process_server_packet(storage: *mut CoreStorage) {
    let next_index = ((*storage).rx_head + 1) % 1024;
    if next_index != (*storage).rx_tail {
        let head_ptr = &raw mut (*storage).buffer_matrix[(*storage).rx_head as usize];
        
        asm!(
            "vpxord zmm0, zmm0, zmm0",       
            "vmovdqu64 zmm1, [{input}]",     
            "vpcmpeqb k1, zmm1, zmm0",       
            "kmovw eax, k1",                 
            "mov byte ptr [{ptr}], 0x55",   
            input = in(reg) head_ptr,
            ptr = in(reg) head_ptr,
            out("eax") _,
            options(nostack)
        );

        asm!(
            "clflush [{ptr}]",
            "sfence",
            ptr = in(reg) head_ptr,
            options(nostack, nomem)
        );

        (*storage).rx_head = next_index;

        let doorbell_addr = PCIE_NIC_BAR0_BASE + NIC_REG_RX_DOORBELL;
        asm!(
            "mov [{addr}], {val:e}", 
            addr = in(reg) doorbell_addr,
            val = in(reg) next_index,
            options(nostack, nomem)
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn handle_vector_14_page_fault() {
    asm!(
        "pushfq", "push rax", "push rbx", "push rcx", "push rdx", 
        "mov rax, cr2",  
        "mov dword ptr [rax], 0", 
        "pop rdx", "push rcx", "pop rbx", "pop rax", "popfq", 
        "iretq", 
        options(noreturn)
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop { unsafe { asm!("hlt", options(noreturn)) }; } }
