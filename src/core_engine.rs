#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_SERVER_CORES: usize = 128;
const NVME_SQ0_TAIL_DOORBELL: u64 = 0x1000;
const GPU_REG_COMPUTE_DOORBELL: u64 = 0x2000;

static DYNAMIC_NIC_BAR0: AtomicU64 = AtomicU64::new(0xFE00_0000);
static DYNAMIC_NVME_BAR0: AtomicU64 = AtomicU64::new(0xFD00_0000);
static DYNAMIC_GPU_BAR0: AtomicU64 = AtomicU64::new(0xF740_0000);
static DYNAMIC_GPU_VRAM_BAR2: AtomicU64 = AtomicU64::new(0xD000_0000);

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

#[repr(C, packed)]
pub struct Ipv4TcpHeader {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_res: u8,
    pub tcp_flags: u8,
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
        "mov dx, 0xCF8", "out dx, eax", "mov dx, 0xCFC", "in eax, dx",
        in("eax") address, lateout("eax") value, out("dx") _, options(nostack, nomem)
    );
    value
}

#[inline(always)]
unsafe fn pci_config_write32(bus: u32, dev: u32, func: u32, offset: u32, value: u32) {
    let address: u32 = 0x8000_0000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    asm!(
        "mov dx, 0xCF8", "out dx, eax", "mov dx, 0xCFC", "mov eax, {val:e}", "out dx, eax",
        in("eax") address, val = in(reg) value, out("dx") _, options(nostack, nomem)
    );
}

pub unsafe fn enumerate_pcie_bus_cold_boot() {
    let mut bus: u32 = 0;
    while bus < 16 {
        let mut dev: u32 = 0;
        while dev < 32 {
            let vd = pci_config_read32(bus, dev, 0, 0x00);
            if (vd & 0xFFFF) != 0xFFFF {
                let base_class = (pci_config_read32(bus, dev, 0, 0x08) >> 24) & 0xFF;
                let bar0_l = pci_config_read32(bus, dev, 0, 0x10) & 0xFFFF_FFF0;
                let bar0_h = pci_config_read32(bus, dev, 0, 0x14);
                let full_bar0 = ((bar0_h as u64) << 32) | (bar0_l as u64);
                if full_bar0 != 0 {
                    let cmd = pci_config_read32(bus, dev, 0, 0x04);
                    pci_config_write32(bus, dev, 0, 0x04, cmd | 0x0006);
                    if base_class == 0x02 { DYNAMIC_NIC_BAR0.store(full_bar0, Ordering::Release); }
                    else if base_class == 0x01 { DYNAMIC_NVME_BAR0.store(full_bar0, Ordering::Release); }
                    else if base_class == 0x03 {
                        DYNAMIC_GPU_BAR0.store(full_bar0, Ordering::Release);
                        let bar2_l = pci_config_read32(bus, dev, 0, 0x18) & 0xFFFF_FFF0;
                        let bar2_h = pci_config_read32(bus, dev, 0, 0x1C);
                        let full_bar2 = ((bar2_h as u64) << 32) | (bar2_l as u64);
                        if full_bar2 != 0 { DYNAMIC_GPU_VRAM_BAR2.store(full_bar2, Ordering::Release); }
                    }
                }
            }
            dev += 1;
        }
        bus += 1;
    }
}

#[inline(always)]
pub unsafe fn shield_inline_normalizer(
    pkt_ptr: *mut Ipv4TcpHeader,
    expected_ttl: u8,
    tsc_timestamp: u64,
    storage: *mut CoreStorage,
    gpu_bar0: u64,
    nvme_bar0: u64,
) -> u8 {
    let flags = core::ptr::read_volatile(&(*pkt_ptr).tcp_flags);
    let ttl = core::ptr::read_volatile(&(*pkt_ptr).ttl);
    let mut normalized_mask: u8 = 0;

    // Фаза 3: Null-пакет (0x00) -> Инжекция ACK (0x10) + сброс SIEM дампа через movnti
    if flags == 0x00 {
        core::ptr::write_volatile(&mut (*pkt_ptr).tcp_flags, 0x10);
        normalized_mask |= 0x01;

        let raw_dword = core::ptr::read_volatile(pkt_ptr as *const u32);
        let dma_dst = &raw mut NVME_OFFLOAD_DMA.slots as *mut u32;
        let nvme_db = (nvme_bar0 + NVME_SQ0_TAIL_DOORBELL) as *mut u32;

        asm!(
            "movnti [{dst}], {val:e}",
            "sfence",
            dst = in(reg) dma_dst,
            val = in(reg) raw_dword,
            options(nostack)
        );
        core::ptr::write_volatile(nvme_db, 1);
    }

    // Фаза 2: Скачок TTL (90 -> 65) -> Выравнивание метрик L3
    if ttl != expected_ttl {
        core::ptr::write_volatile(&mut (*pkt_ptr).ttl, expected_ttl);
        normalized_mask |= 0x02;
    }

    // Разгрузка IAT / Entropy на GPU (iGPU / GTX 1050) в обход кэша ЦП
    let iat_slot = &raw mut (*storage).ddr_trap_pad as *mut u64;
    let trap_pad_next = (&raw mut (*storage).ddr_trap_pad as *mut u8).add(64);
    asm!(
        "movnti [{slot}], {ts}",
        "prefetchw [{next_pad}]",
        "sfence",
        slot = in(reg) iat_slot,
        ts = in(reg) tsc_timestamp,
        next_pad = in(reg) trap_pad_next,
        options(nostack)
    );

    let gpu_db = (gpu_bar0 + GPU_REG_COMPUTE_DOORBELL) as *mut u32;
    core::ptr::write_volatile(gpu_db, 1);

    normalized_mask
}

#[repr(C, align(4096))]
struct MockMmioPage([u8; 0x3000]);

static mut MOCK_NVME_MMIO: MockMmioPage = MockMmioPage([0; 0x3000]);
static mut MOCK_GPU_MMIO: MockMmioPage = MockMmioPage([0; 0x3000]);

pub fn simulate_shield_rack_benchmark() -> (u64, u64, u8, u8) {
    unsafe {
        let nvme_bar0 = (&raw mut MOCK_NVME_MMIO.0 as *mut u8) as u64;
        let gpu_bar0 = (&raw mut MOCK_GPU_MMIO.0 as *mut u8) as u64;
        let storage = (&raw mut SERVER_CORE_MATRIX as *mut CoreStorage).add(0);

        // Прогрев страниц и TLB
        core::ptr::write_volatile((nvme_bar0 + NVME_SQ0_TAIL_DOORBELL) as *mut u32, 0);
        core::ptr::write_volatile((gpu_bar0 + GPU_REG_COMPUTE_DOORBELL) as *mut u32, 0);
        core::ptr::write_volatile(&raw mut NVME_OFFLOAD_DMA.slots as *mut u32, 0);
        core::ptr::write_volatile(&raw mut (*storage).ddr_trap_pad[0], 0);

        let pkt_ptr = &raw mut (*storage).buffer_matrix as *mut Ipv4TcpHeader;

        // 1. Тест Аномального пакета (Фаза 2: TTL=90 + Фаза 3: TCP Flags = 0x00)
        core::ptr::write_volatile(&mut (*pkt_ptr).ttl, 90);
        core::ptr::write_volatile(&mut (*pkt_ptr).tcp_flags, 0x00);

        let ts1 = crate::tsc::rdtsc_start();
        let (mask_anomaly, anomaly_cycles) = crate::tsc::measure_cycles(|| {
            shield_inline_normalizer(pkt_ptr, 65, ts1, storage, gpu_bar0, nvme_bar0)
        });
        let fixed_flags = core::ptr::read_volatile(&(*pkt_ptr).tcp_flags);

        // 2. Тест Легитимного пакета (Фаза 1: TTL=65, ACK=0x10)
        core::ptr::write_volatile(&mut (*pkt_ptr).ttl, 65);
        core::ptr::write_volatile(&mut (*pkt_ptr).tcp_flags, 0x10);

        let ts2 = crate::tsc::rdtsc_start();
        let (_mask_clean, clean_cycles) = crate::tsc::measure_cycles(|| {
            shield_inline_normalizer(pkt_ptr, 65, ts2, storage, gpu_bar0, nvme_bar0)
        });

        (anomaly_cycles, clean_cycles, mask_anomaly, fixed_flags)
    }
}

#[allow(suspicious_runtime_symbol_definitions)]
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    asm!("cld", "rep stosb", inout("rdi") dest => _, in("al") val as u8, inout("rcx") count => _, options(nostack));
    dest
}

#[allow(suspicious_runtime_symbol_definitions)]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    asm!("cld", "rep movsb", inout("rdi") dest => _, inout("rsi") src => _, inout("rcx") count => _, options(nostack));
    dest
}
