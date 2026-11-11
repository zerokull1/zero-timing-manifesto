#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_SERVER_CORES: usize = 128;
const NIC_REG_RX_DOORBELL: u64 = 0x1008;
const ATTACK_SIGNATURE_BYTE: u8 = 0xDE;

static DYNAMIC_NIC_BAR0: AtomicU64 = AtomicU64::new(0xFE000000);
static DYNAMIC_NVME_BAR0: AtomicU64 = AtomicU64::new(0xFD000000);

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(align(4096))]
pub struct CoreStorage {
    tx_head: u32,
    tx_tail: u32,
    rx_head: u32,
    rx_tail: u32,
    buffer_matrix: [u8; 1024],
    ddr_trap_pad: [u8; 3056], 
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

// Жесткая привязка к регистру eax для аппаратных портов 0xCF8 / 0xCFC
#[inline(always)]
unsafe fn pci_config_read32(bus: u32, dev: u32, func: u32, offset: u32) -> u32 {
    let address: u32 = 0x80000000
        | (bus << 16)
        | (dev << 11)
        | (func << 8)
        | (offset & 0xFC);
    let mut value: u32;
    asm!(
        "mov dx, 0xCF8",
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        in("eax") address,
        lateout("eax") value,
        out("dx") _,
        options(nostack, nomem)
    );
    value
}

#[inline(always)]
unsafe fn pci_config_write32(bus: u32, dev: u32, func: u32, offset: u32, value: u32) {
    let address: u32 = 0x80000000
        | (bus << 16)
        | (dev << 11)
        | (func << 8)
        | (offset & 0xFC);
    asm!(
        "mov dx, 0xCF8",
        "out dx, eax",
        "mov dx, 0xCFC",
        "mov eax, {val:e}",
        "out dx, eax",
        in("eax") address,
        val = in(reg) value,
        out("dx") _,
        options(nostack, nomem)
    );
}

unsafe fn enumerate_pcie_bus_cold_boot() {
    let mut bus: u32 = 0;
    while bus < 16 {
        let mut dev: u32 = 0;
        while dev < 32 {
            let vendor_device = pci_config_read32(bus, dev, 0, 0x00);
            if (vendor_device & 0xFFFF) != 0xFFFF {
                let class_rev = pci_config_read32(bus, dev, 0, 0x08);
                let base_class = (class_rev >> 24) & 0xFF;

                let bar0_low = pci_config_read32(bus, dev, 0, 0x10) & 0xFFFFFFF0;
                let bar0_high = pci_config_read32(bus, dev, 0, 0x14);
                let full_bar0 = ((bar0_high as u64) << 32) | (bar0_low as u64);

                if full_bar0 != 0 {
                    let cmd = pci_config_read32(bus, dev, 0, 0x04);
                    pci_config_write32(bus, dev, 0, 0x04, cmd | 0x0006);

                    if base_class == 0x02 {
                        DYNAMIC_NIC_BAR0.store(full_bar0, Ordering::Release);
                    } else if base_class == 0x01 {
                        DYNAMIC_NVME_BAR0.store(full_bar0, Ordering::Release);
                    }
                }
            }
            dev += 1;
        }
        bus += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        "cli",
        "mfence",
        "mov rax, cr0", "and rax, 0xFFFFFFFFFFFEFFFF", "mov cr0, rax",
        "mov rax, cr4", "or rax, 0x0000000000000080", "mov cr4, rax",
        options(nostack)
    );

    enumerate_pcie_bus_cold_boot();

    let interface_flags = XDP_FLAGS_DRV_MODE;
    asm!("mov edx, {flags:e}", "out dx, al", flags = in(reg) interface_flags, options(nostack));

    let matrix_base_ptr = &raw mut SERVER_CORE_MATRIX;

    let mut core_idx = 0;
    while core_idx < MAX_SERVER_CORES {
        let warm_ptr = &raw mut SERVER_CORE_MATRIX[core_idx].buffer_matrix;
        asm!(
            "prefetchw [{ptr}]", 
            "mov byte ptr [{ptr}], 0",
            ptr = in(reg) warm_ptr,
            options(nostack, nomem)
        );
        core_idx += 1;
    }
    asm!("mfence", options(nostack, nomem));

    let nic_bar0 = DYNAMIC_NIC_BAR0.load(Ordering::Acquire);
    let nvme_bar0 = DYNAMIC_NVME_BAR0.load(Ordering::Acquire);

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

        asm!(
            "mov eax, {id:e}",
            "and rax, 0x7F",        
            "shl rax, 12",          
            "add rax, {base}",      
            "mov {out_ptr}, rax",   
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
        
        process_server_packet(target_core_storage_ptr, nic_bar0, nvme_bar0);
        process_server_packet(target_core_storage_ptr, nic_bar0, nvme_bar0);
        
        asm!("pause", options(nostack, nomem));
    }
}

#[inline(always)]
unsafe fn process_server_packet(storage: *mut CoreStorage, nic_bar0: u64, nvme_bar0: u64) {
    let next_index = ((*storage).rx_head + 1) % 1024;
    if next_index != (*storage).rx_tail {
        let head_ptr = &raw mut (*storage).buffer_matrix[(*storage).rx_head as usize];
        
        let signature_pattern: u32 = ATTACK_SIGNATURE_BYTE as u32;
        let mut match_mask: u16;

        asm!(
            "vmovd xmm0, {sig:e}",          
            "vpbroadcastb zmm0, xmm0",      
            "vmovdqu64 zmm1, [{input}]",     
            "vpcmpeqb k1, zmm1, zmm0",       
            "kmovw {mask:e}, k1",            
            sig = in(reg) signature_pattern,
            input = in(reg) head_ptr,
            mask = out(reg) match_mask,
            out("zmm0") _, out("zmm1") _, out("k1") _
        );

        if match_mask != 0 {
            let ssd_offload_addr = nvme_bar0 + (((*storage).rx_head as u64) << 3);
            let trap_ptr = &raw mut (*storage).ddr_trap_pad;
            asm!(
                "movnti [{ssd}], {mask_val}",
                "prefetchw [{trap}]",
                ssd = in(reg) ssd_offload_addr,
                mask_val = in(reg) (match_mask as u64),
                trap = in(reg) trap_ptr,
                options(nostack, nomem)
            );
            return;
        }

        *head_ptr = 0x55;

        asm!(
            "clflush [{ptr}]",
            "sfence",
            ptr = in(reg) head_ptr,
            options(nostack, nomem)
        );

        (*storage).rx_head = next_index;

        let doorbell_addr = nic_bar0 + NIC_REG_RX_DOORBELL;
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
fn panic(_info: &PanicInfo) -> ! { loop { unsafe { asm!("pause", options(nostack, nomem)) }; } }
