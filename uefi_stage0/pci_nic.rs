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
