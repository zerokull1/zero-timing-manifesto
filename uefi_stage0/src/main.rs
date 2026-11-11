#![no_std]
#![no_main]

use core::arch::asm;
use uefi::prelude::*;
use uefi::CStr16;

#[inline(always)]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nomem, nostack));
}

/// Аппаратная блокировка скачков частоты и напряжения (Anti-Morse Side-Channel Power Lock)
#[inline(always)]
unsafe fn lock_isochronous_power_msr() -> u32 {
    // 1. Отключаем динамический Turbo Boost (бит 38 в IA32_MISC_ENABLE = 0x1A0)
    let misc = rdmsr(0x1A0);
    wrmsr(0x1A0, misc | (1u64 << 38));

    // 2. Читаем номинальный P-State из IA32_PERF_STATUS (0x198) и фиксируем в IA32_PERF_CTL (0x199)
    let perf_status = rdmsr(0x198);
    let target_pstate = perf_status & 0xFFFF;
    wrmsr(0x199, target_pstate);

    target_pstate as u32
}

#[inline(always)]
unsafe fn pcie_read32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xFC)
        | 0x8000_0000;
    let data: u32;
    asm!(
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        inout("dx") 0x0CF8 => _,
        inout("eax") addr => data,
        options(nostack, nomem)
    );
    data
}

#[inline(always)]
unsafe fn pcie_write32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xFC)
        | 0x8000_0000;
    asm!(
        "mov dx, 0xCF8",
        "out dx, eax",
        "mov dx, 0xCFC",
        "mov eax, {v:e}",
        "out dx, eax",
        in("eax") addr,
        v = in(reg) val,
        out("dx") _,
        options(nostack, nomem)
    );
}

fn to_hex16(val: u64, digits: usize, buf: &mut [u16; 19]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut it = buf.iter_mut();
    *it.next().unwrap() = 48;
    *it.next().unwrap() = 120;
    for i in 0..digits {
        let shift = (digits - 1 - i) * 4;
        *it.next().unwrap() = HEX[((val >> shift) & 0xF) as usize] as u16;
    }
    *it.next().unwrap() = 0;
}

#[inline(always)]
unsafe fn rdtsc_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[entry]
fn main(_image_handle: Handle, mut st: SystemTable<Boot>) -> Status {
    let out = st.stdout();
    out.reset(false).unwrap();
    out.output_string(uefi::cstr16!("=== ZERO-TIMING BARE-METAL RING 0 BOOT (UEFI) ===\r\n")).unwrap();

    let mut buf = [0u16; 19];

    unsafe {
        // 1. Блокируем скачки напряжения/частоты (Anti-Morse MSR Power Lock)
        let locked_pstate = lock_isochronous_power_msr();
        out.output_string(uefi::cstr16!("[Anti-Morse MSR] P-State Locked (0x199): ")).unwrap();
        to_hex16(locked_pstate as u64, 4, &mut buf);
        let sl_p = core::slice::from_raw_parts(buf.as_ptr(), 7);
        out.output_string(CStr16::from_u16_with_nul(sl_p).unwrap()).unwrap();
        out.output_string(uefi::cstr16!("\r\n")).unwrap();

        // 2. Холодный скан шины PCIe (NIC/NVMe/GPU) + активация Bus Master DMA
        for bus in 0..16u8 {
            for dev in 0..32u8 {
                let vd = pcie_read32(bus, dev, 0, 0x00);
                if (vd & 0xFFFF) != 0xFFFF {
                    let class = (pcie_read32(bus, dev, 0, 0x08) >> 24) & 0xFF;
                    let bar0 = pcie_read32(bus, dev, 0, 0x10) & 0xFFFF_FFF0;
                    if bar0 != 0 && (class == 0x01 || class == 0x02 || class == 0x03) {
                        let cmd = pcie_read32(bus, dev, 0, 0x04);
                        pcie_write32(bus, dev, 0, 0x04, cmd | 0x0006);

                        if class == 0x02 {
                            out.output_string(uefi::cstr16!("[PCIe NIC ] BAR0: ")).unwrap();
                        } else if class == 0x01 {
                            out.output_string(uefi::cstr16!("[PCIe NVMe] BAR0: ")).unwrap();
                        } else {
                            out.output_string(uefi::cstr16!("[PCIe GPU ] BAR0: ")).unwrap();
                        }

                        to_hex16(bar0 as u64, 8, &mut buf);
                        let sl = core::slice::from_raw_parts(buf.as_ptr(), 11);
                        out.output_string(CStr16::from_u16_with_nul(sl).unwrap()).unwrap();
                        out.output_string(uefi::cstr16!(" (BusMaster ON)\r\n")).unwrap();
                    }
                }
            }
        }

        // 3. Замер Active Inline Shield в чистом Ring 0
        let mut fake_pkt: u32 = 0x0000_005A;
        let mut dma_slot: u32 = 0;
        let t0 = rdtsc_serialized();
        let raw = core::ptr::read_volatile(&fake_pkt);
        if (raw & 0xFF) != 65 {
            core::ptr::write_volatile(&mut fake_pkt, (raw & !0xFF) | 65);
        }
        asm!("movnti [{dst}], {v:e}", "sfence", dst = in(reg) &mut dma_slot, v = in(reg) raw, options(nostack));
        let t1 = rdtsc_serialized();

        out.output_string(uefi::cstr16!("[Ring 0 Shield] Active Norm + movnti: ")).unwrap();
        to_hex16(t1.saturating_sub(t0), 4, &mut buf);
        let sl2 = core::slice::from_raw_parts(buf.as_ptr(), 7);
        out.output_string(CStr16::from_u16_with_nul(sl2).unwrap()).unwrap();
        out.output_string(uefi::cstr16!(" cycles (hex)\r\n")).unwrap();
    }

    st.boot_services().stall(1_000_000);
    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
