#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_SERVER_CORES: usize = 128;
const NIC_REG_RX_DOORBELL: u64 = 0x1008;
const NVME_SQ0_TAIL_DOORBELL: u64 = 0x1000;
const ATTACK_SIGNATURE_DWORD: u32 = 0xDEADBEEF;

static DYNAMIC_NIC_BAR0: AtomicU64 = AtomicU64::new(0xFE00_0000);
static DYNAMIC_NVME_BAR0: AtomicU64 = AtomicU64::new(0xFD00_0000);

#[derive(Copy, Clone)]
#[repr(C, align(4096))]
pub struct CoreStorage {
    pub tx_head: u32,
    pub tx_tail: u32,
    pub rx_head: u32,
    pub rx_tail: u32,
    pub buffer_matrix: [u8; 1024],
    pub ddr_trap_pad: [u8; 3056],
}

#[repr(C, align(4096))]
pub struct NvmeOffloadPage {
    pub slots: [u32; 1024],
}

static mut SERVER_CORE_MATRIX: [CoreStorage; MAX_SERVER_CORES] = [CoreStorage {
    tx_head: 0,
    tx_tail: 0,
    rx_head: 0,
    rx_tail: 0,
    buffer_matrix: [0; 1024],
    ddr_trap_pad: [0; 3056],
}; MAX_SERVER_CORES];

static mut NVME_OFFLOAD_DMA: NvmeOffloadPage = NvmeOffloadPage { slots: [0; 1024] };

#[inline(always)]
unsafe fn pci_config_read32(bus: u32, dev: u32, func: u32, offset: u32) -> u32 {
    let address: u32 = 0x8000_0000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
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
    let address: u32 = 0x8000_0000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
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

pub unsafe fn enumerate_pcie_bus_cold_boot() {
    let mut bus: u32 = 0;
    while bus < 16 {
        let mut dev: u32 = 0;
        while dev < 32 {
            let vendor_device = pci_config_read32(bus, dev, 0, 0x00);
            if (vendor_device & 0xFFFF) != 0xFFFF {
                let class_rev = pci_config_read32(bus, dev, 0, 0x08);
                let base_class = (class_rev >> 24) & 0xFF;

                let bar0_low = pci_config_read32(bus, dev, 0, 0x10) & 0xFFFF_FFF0;
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

#[inline(always)]
unsafe fn fast_core_id() -> u32 {
    let aux_id: u32;
    asm!(
        "rdtscp",
        out("eax") _,
        out("edx") _,
        out("ecx") aux_id,
        options(nostack, nomem)
    );
    aux_id & 0x7F
}

pub unsafe fn run_bare_metal_loop() -> ! {
    asm!(
        "cli",
        "mfence",
        "mov rax, cr0",
        "and rax, 0xFFFFFFFFFFFEFFFF",
        "mov cr0, rax",
        "mov rax, cr4",
        "or rax, 0x0000000000000080",
        "mov cr4, rax",
        options(nostack)
    );

    enumerate_pcie_bus_cold_boot();

    let matrix_base_ptr = &raw mut SERVER_CORE_MATRIX as *mut CoreStorage;

    let mut core_idx = 0;
    while core_idx < MAX_SERVER_CORES {
        let warm_ptr = &raw mut (*matrix_base_ptr.add(core_idx)).buffer_matrix;
        asm!(
            "prefetchw [{ptr}]",
            "mov byte ptr [{ptr}], 0",
            ptr = in(reg) warm_ptr,
            options(nostack)
        );
        core_idx += 1;
    }
    asm!("mfence", options(nostack));

    let nic_bar0 = DYNAMIC_NIC_BAR0.load(Ordering::Acquire);
    let nvme_bar0 = DYNAMIC_NVME_BAR0.load(Ordering::Acquire);

    loop {
        let core_id = fast_core_id();
        let target_core_storage_ptr = matrix_base_ptr.add(core_id as usize);

        let next_core_index = ((core_id as usize) + 1) & 0x7F;
        let next_storage_ptr = matrix_base_ptr.add(next_core_index);
        asm!(
            "prefetcht0 [{ptr}]",
            ptr = in(reg) next_storage_ptr,
            options(nostack)
        );

        process_server_packet(target_core_storage_ptr, nic_bar0, nvme_bar0);
        process_server_packet(target_core_storage_ptr, nic_bar0, nvme_bar0);

        asm!("pause", options(nostack, nomem));
    }
}

#[inline(always)]
unsafe fn process_server_packet(storage: *mut CoreStorage, nic_bar0: u64, nvme_bar0: u64) {
    let aligned_offset = ((*storage).rx_head as usize) & !3;
    let next_index = ((*storage).rx_head + 4) & 1023;

    if next_index != (*storage).rx_tail {
        let head_ptr = (&raw mut (*storage).buffer_matrix as *mut u8).add(aligned_offset);
        let mut is_trapped: u32;

        asm!(
            "mov eax, [{input}]",
            "cmp eax, {sig:e}",
            "sete {trap_flag}",
            "movzx {res:e}, {trap_flag}",
            input = in(reg) head_ptr,
            sig = in(reg) ATTACK_SIGNATURE_DWORD,
            trap_flag = out(reg_byte) _,
            res = out(reg) is_trapped,
            out("eax") _,
            options(nostack, readonly)
        );

        if is_trapped != 0 {
            let dma_slot_idx = aligned_offset >> 2;
            let dma_dst_ptr = (&raw mut NVME_OFFLOAD_DMA.slots as *mut u32).add(dma_slot_idx);
            let trap_ptr = &raw mut (*storage).ddr_trap_pad;
            let nvme_doorbell = nvme_bar0 + NVME_SQ0_TAIL_DOORBELL;

            asm!(
                "movnti [{dma}], {sig:e}",
                "prefetchw [{trap}]",
                "sfence",
                "mov [{db}], {tail:e}",
                dma = in(reg) dma_dst_ptr,
                sig = in(reg) ATTACK_SIGNATURE_DWORD,
                trap = in(reg) trap_ptr,
                db = in(reg) nvme_doorbell,
                tail = in(reg) ((dma_slot_idx + 1) as u32),
                options(nostack)
            );

            (*storage).rx_head = next_index;
            return;
        }

        core::ptr::write_volatile(head_ptr as *mut u32, 0x5555_5555);

        asm!(
            "clflush [{ptr}]",
            "sfence",
            ptr = in(reg) head_ptr,
            options(nostack)
        );

        (*storage).rx_head = next_index;

        let doorbell_addr = nic_bar0 + NIC_REG_RX_DOORBELL;
        asm!(
            "mov [{addr}], {val:e}",
            addr = in(reg) doorbell_addr,
            val = in(reg) next_index,
            options(nostack)
        );
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn handle_vector_14_page_fault() {
    core::arch::naked_asm!(
        "add rsp, 8",
        "iretq"
    );
}

#[repr(C, align(4096))]
struct MockMmioPage([u8; 0x2000]);

static mut MOCK_NIC_MMIO: MockMmioPage = MockMmioPage([0; 0x2000]);
static mut MOCK_NVME_MMIO: MockMmioPage = MockMmioPage([0; 0x2000]);

pub fn simulate_ddr_trap_benchmark() -> (u64, u64, u32, u32) {
    unsafe {
        let nic_bar0 = (&raw mut MOCK_NIC_MMIO.0 as *mut u8) as u64;
        let nvme_bar0 = (&raw mut MOCK_NVME_MMIO.0 as *mut u8) as u64;

        let storage = (&raw mut SERVER_CORE_MATRIX as *mut CoreStorage).add(0);
        (*storage).rx_head = 0;
        (*storage).rx_tail = 16;

        let buf_ptr = &raw mut (*storage).buffer_matrix as *mut u32;
        core::ptr::write_volatile(buf_ptr.add(0), ATTACK_SIGNATURE_DWORD);
        core::ptr::write_volatile(buf_ptr.add(1), 0x1122_3344);

        // Прогрев страниц памяти и TLB (убираем Minor Page Faults перед замером)
        core::ptr::write_volatile((nvme_bar0 + NVME_SQ0_TAIL_DOORBELL) as *mut u32, 0);
        core::ptr::write_volatile((nic_bar0 + NIC_REG_RX_DOORBELL) as *mut u32, 0);
        let dma_warm = &raw mut NVME_OFFLOAD_DMA.slots as *mut u32;
        core::ptr::write_volatile(dma_warm.add(0), 0);
        core::ptr::write_volatile(&raw mut (*storage).ddr_trap_pad[0], 0);

        let (_, trap_cycles) = crate::tsc::measure_cycles(|| {
            process_server_packet(storage, nic_bar0, nvme_bar0);
        });

        let (_, clean_cycles) = crate::tsc::measure_cycles(|| {
            process_server_packet(storage, nic_bar0, nvme_bar0);
        });

        let dma_ptr = &raw const NVME_OFFLOAD_DMA.slots as *const u32;
        let offloaded_dword = core::ptr::read_volatile(dma_ptr.add(0));
        let nvme_db_val = core::ptr::read_volatile((nvme_bar0 + NVME_SQ0_TAIL_DOORBELL) as *const u32);

        (trap_cycles, clean_cycles, offloaded_dword, nvme_db_val)
    }
}

#[allow(suspicious_runtime_symbol_definitions)]
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    asm!(
        "cld",
        "rep stosb",
        inout("rdi") dest => _,
        in("al") val as u8,
        inout("rcx") count => _,
        options(nostack)
    );
    dest
}

#[allow(suspicious_runtime_symbol_definitions)]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    asm!(
        "cld",
        "rep movsb",
        inout("rdi") dest => _,
        inout("rsi") src => _,
        inout("rcx") count => _,
        options(nostack)
    );
    dest
}
