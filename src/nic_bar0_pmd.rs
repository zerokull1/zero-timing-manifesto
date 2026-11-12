#![allow(dead_code)]

use core::arch::asm;

// Стандартные MMIO-смещения регистров кольца приёма (RX Ring) в BAR0 сетевых карт Intel (e1000e/igb/ixgbe)
const REG_CTRL: usize  = 0x0000;
const REG_STATUS: usize = 0x0008;
const REG_RCTL: usize  = 0x0100;
const REG_RDBAL: usize = 0x2800; // Базовый адрес RX-дескрипторов (младшие 32 бита)
const REG_RDBAH: usize = 0x2804; // Базовый адрес RX-дескрипторов (старшие 32 бита)
const REG_RDLEN: usize = 0x2808; // Длина кольца дескрипторов в байтах
const REG_RDH: usize   = 0x2810; // Head (указатель, куда пишет сама сетевая карта)
const REG_RDT: usize   = 0x2818; // Tail (указатель, до которого вычитал наш движок)

#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct HardwareRxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

#[inline(always)]
unsafe fn mmio_read32(bar0_virt: usize, offset: usize) -> u32 { unsafe {
    core::ptr::read_volatile((bar0_virt + offset) as *const u32)
}}

#[inline(always)]
unsafe fn mmio_write32(bar0_virt: usize, offset: usize, val: u32) { unsafe {
    core::ptr::write_volatile((bar0_virt + offset) as *mut u32, val);
}}

/// Прямой бездрайверный опрос аппаратного кольца NIC через MMIO BAR0 (OS-Agnostic PMD)
/// Работает одинаково поверх UEFI, Linux (VFIO/UIO) и Windows (WinRing0/Kernel).
#[inline(always)]
pub unsafe fn poll_nic_bar0_ring(
    bar0_virt: usize,
    ring_base: *mut HardwareRxDesc,
    ring_mask: u32,
    sw_tail: &mut u32,
    ddr_siem_slot: *mut u32,
) -> u32 { unsafe {
    let idx = (*sw_tail + 1) & ring_mask;
    let desc_ptr = ring_base.add(idx as usize);
    let status = core::ptr::read_volatile(&(*desc_ptr).status);

    // Бит 0 (Descriptor Done) выставляется самим кремнием сетевой карты по шине PCIe DMA
    if (status & 0x01) == 0 {
        return 0;
    }

    let pkt_len = core::ptr::read_volatile(&(*desc_ptr).length) as u32;
    let pkt_ptr = core::ptr::read_volatile(&(*desc_ptr).buffer_addr) as *const u8;

    // Динамический расчёт границ L3/L4 (защита от IP/TCP Options и IP-фрагментации)
    if pkt_len >= 70 && !pkt_ptr.is_null() {
        let ihl = ((*pkt_ptr.add(14)) & 0x0F) as u32 * 4;
        let frag = u16::from_be(core::ptr::read_unaligned(pkt_ptr.add(20) as *const u16));
        let tcp_off = 14 + ihl;
        if ihl >= 20 && (frag & 0x3FFF) == 0 && pkt_len >= tcp_off + 20 {
            let tcp_doff = (((*pkt_ptr.add((tcp_off + 12) as usize)) >> 4) as u32) * 4;
            let l7_off = tcp_off + tcp_doff;
            if tcp_doff >= 20 && pkt_len >= l7_off + 16 {
                let verdict = crate::l7_shield::inspect_l7_payload_asm(
                    pkt_ptr.add(l7_off as usize),
                    (pkt_len - l7_off) as usize,
                    80,
                );
        asm!(
            "movnti [{dst}], {v:e}",
            "sfence",
            dst = in(reg) ddr_siem_slot,
            v = in(reg) verdict as u32,
            options(nostack)
                );
            }
        }
    }

    // Сбрасываем статус дескриптора и сдвигаем аппаратный хвост RDT напрямую в BAR0
    core::ptr::write_volatile(&mut (*desc_ptr).status, 0);
    *sw_tail = idx;
    if bar0_virt != 0 {
        mmio_write32(bar0_virt, REG_RDT, idx);
    }

    pkt_len
}}
