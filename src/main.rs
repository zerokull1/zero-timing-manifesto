#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;

const MAX_SERVER_CORES: usize = 128;

// Базовый адрес MMIO-регистров управления сетевой карты в физическом пространстве
const PCIE_NIC_BAR0_BASE: u64 = 0xFE000000; 
// Смещение регистра Doorbell (уведомление карты о наличии новых дескрипторов в кольце)
const NIC_REG_RX_DOORBELL: u64 = 0x1008;

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(align(4096))]
pub struct CoreStorage {
    tx_head: u32,
    tx_tail: u32,
    rx_head: u32,
    rx_tail: u32,
    buffer_matrix: [u8; 1024],
    ddr_trap_pad: [u8; 4096], 
}

static mut SERVER_CORE_MATRIX: [CoreStorage; MAX_SERVER_CORES] = {
    let mut i = 0;
    let mut matrix = [CoreStorage {
        tx_head: 0, tx_tail: 0, rx_head: 0, rx_tail: 0,
        buffer_matrix: [0; 1024],
        ddr_trap_pad: [0; 4096],
    }; MAX_SERVER_CORES];
    
    while i < MAX_SERVER_CORES {
        matrix[i] = CoreStorage {
            tx_head: 0, tx_tail: 0, rx_head: 0, rx_tail: 0,
            buffer_matrix: [0; 1024],
            ddr_trap_pad: [0; 4096],
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

    // ИНИЦИАЛИЗАЦИЯ ШИННОГО АРБИТРАЖА (PCI EXPRESS BUS MASTER ENABLE)
    // Конфигурационный порт PCI: 0xCF8 (Address), 0xCFC (Data)
    // Включаем Bit 2 (Bus Master) и Bit 1 (Memory Space) в командном регистре устройства
    asm!(
        "mov eax, 0x80000004", // Пример адресации: Bus 0, Device 0, Function 0, Register 0x04
        "mov dx, 0xCF8",
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        "or eax, 0x0006",     // Выставляем флаги Bus Master и Memory Space Enable
        "out dx, eax",
        options(nostack)
    );

    let interface_flags = XDP_FLAGS_DRV_MODE;
    asm!("mov edx, {flags:e}", "out dx, al", flags = in(reg) interface_flags, options(nostack));

    loop {
        let mut core_id: u32;
        let mut _tmp_rbx: u64;
        
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

        let core_index = (core_id as usize) % MAX_SERVER_CORES;
        let next_core_index = (core_index + 1) % MAX_SERVER_CORES;
        
        let next_storage_ptr = &raw mut SERVER_CORE_MATRIX[next_core_index];
        asm!(
            "prefetcht0 [{ptr}]",
            ptr = in(reg) next_storage_ptr,
            options(nostack, nomem)
        );
        
        asm!("lfence", options(nostack, nomem));
        
        process_server_packet(&raw mut SERVER_CORE_MATRIX[core_index]);
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

        // ШИННЫЙ АРБИТРАЖ: Уведомляем сетевой чип по PCIe шине через MMIO регистр Doorbell
        let doorbell_addr = PCIE_NIC_BAR0_BASE + NIC_REG_RX_DOORBELL;
        asm!(
            "mov [{addr}], {val:e}", // Запись нового индекса головы кольца прямо в порт чипа
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
        "pop rdx", "pop rcx", "pop rbx", "pop rax", "popfq", 
        "iretq", 
        options(noreturn)
    );
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { loop { unsafe { asm!("hlt", options(noreturn)) }; } }
