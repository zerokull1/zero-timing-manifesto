// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

#[inline(always)]
unsafe fn pci_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000 | ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | ((offset as u32) & 0xFC)
}

#[inline(always)]
pub unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_addr(bus, dev, func, offset);
    let val: u32;
    asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") addr, options(nostack, nomem));
    asm!("in eax, dx", in("dx") 0xCFCu16, out("eax") val, options(nostack, nomem));
    val
}

#[inline(always)]
pub unsafe fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_addr(bus, dev, func, offset);
    asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") addr, options(nostack, nomem));
    asm!("out dx, eax", in("dx") 0xCFCu16, in("eax") val, options(nostack, nomem));
}

pub unsafe fn probe_intel_nic() -> Option<(usize, [u8; 6], u32)> {
    for bus in 0..=4u8 {
        for dev in 0..32u8 {
            if pci_read32(bus, dev, 0, 0x00) == 0x100E_8086 {
                let bar0 = (pci_read32(bus, dev, 0, 0x10) & 0xFFFF_FFF0) as usize;
                let cmd = pci_read32(bus, dev, 0, 0x04);
                pci_write32(bus, dev, 0, 0x04, cmd | 0x06); // Bus Master + MMIO

                let ral = read_volatile((bar0 + 0x5400) as *const u32);
                let rah = read_volatile((bar0 + 0x5404) as *const u32);
                let mac = [
                    (ral & 0xFF) as u8, ((ral >> 8) & 0xFF) as u8,
                    ((ral >> 16) & 0xFF) as u8, ((ral >> 24) & 0xFF) as u8,
                    (rah & 0xFF) as u8, ((rah >> 8) & 0xFF) as u8,
                ];
                let status = read_volatile((bar0 + 0x0008) as *const u32);
                write_volatile((bar0 + 0x0100) as *mut u32, (1 << 1) | (1 << 15)); // RCTL EN + BAM
                return Some((bar0, mac, status));
            }
        }
    }
    None
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct TxDesc {
    pub addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

static mut TX_RING: [TxDesc; 8] = [TxDesc { addr: 0, length: 0, cso: 0, cmd: 0, status: 0, css: 0, special: 0 }; 8];
static mut TX_PKT: [u8; 64] = [0u8; 64];

pub unsafe fn tx_send_frame(bar0: usize, mac: [u8; 6]) -> u8 {
    TX_PKT[0..6].copy_from_slice(&[0xFF; 6]); // Broadcast dst
    TX_PKT[6..12].copy_from_slice(&mac);       // Src MAC
    TX_PKT[12..14].copy_from_slice(&0x88B5u16.to_be_bytes()); // Custom EtherType
    TX_PKT[14..22].copy_from_slice(b"ZERORING");

    let ring_addr = TX_RING.as_ptr() as u64;
    write_volatile((bar0 + 0x3800) as *mut u32, (ring_addr & 0xFFFF_FFFF) as u32); // TDBAL
    write_volatile((bar0 + 0x3804) as *mut u32, (ring_addr >> 32) as u32);        // TDBAH
    write_volatile((bar0 + 0x3808) as *mut u32, (8 * 16) as u32);                 // TDLEN
    write_volatile((bar0 + 0x3810) as *mut u32, 0);                               // TDH
    write_volatile((bar0 + 0x3818) as *mut u32, 0);                               // TDT
    write_volatile((bar0 + 0x0400) as *mut u32, (1 << 1) | (1 << 3));             // TCTL EN + PSP

    TX_RING[0].addr = TX_PKT.as_ptr() as u64;
    TX_RING[0].length = 64;
    TX_RING[0].cmd = (1 << 0) | (1 << 1) | (1 << 3); // EOP | IFCS | RS
    TX_RING[0].status = 0;

    // Удар в MMIO Doorbell (TDT = 1) -> NIC DMA забирает кадр в провод!
    write_volatile((bar0 + 0x3818) as *mut u32, 1);
    for _ in 0..100_000 {
        let st = read_volatile(&TX_RING[0].status);
        if (st & 0x01) != 0 {
            return st; // Descriptor Done (DD = 1)
        }
        core::hint::spin_loop();
    }
    0
}
