// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![no_std]
#![no_main]
use uefi::CStr16;

use core::arch::asm;
use uefi::prelude::*;
use uefi::boot::{self, AllocateType, MemoryType};

#[inline(always)]
unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn wrmsr(msr: u32, val: u64) {
    asm!("wrmsr", in("ecx") msr, in("eax") val as u32, in("edx") (val >> 32) as u32, options(nomem, nostack));
}

#[inline(always)]
unsafe fn pcie_read32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = ((bus as u32) << 16) | ((slot as u32) << 11) | ((func as u32) << 8) | (offset as u32 & 0xFC) | 0x8000_0000;
    let data: u32;
    asm!("out dx, eax", "mov dx, 0xCFC", "in eax, dx", inout("dx") 0x0CF8 => _, inout("eax") addr => data, options(nostack, nomem));
    data
}

#[inline(always)]
unsafe fn hw_rand64() -> u64 {
    let (mut val, mut ok): (u64, u8) = (0, 0);
    asm!("rdrand {v}", "setc {ok}", v = out(reg) val, ok = out(reg_byte) ok, options(nomem, nostack));
    if ok != 0 && val != 0 { val } else {
        let (lo, hi): (u32, u32);
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        (((hi as u64) << 32) | (lo as u64)).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }
}

fn to_hex16(val: u64, digits: usize, buf: &mut [u16; 19]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    buf[0] = 48; buf[1] = 120;
    for i in 0..digits { buf[i + 2] = HEX[((val >> ((digits - 1 - i) * 4)) & 0xF) as usize] as u16; }
    buf[digits + 2] = 0;
}

#[entry]
fn main() -> Status {
    let mut key_512 = [0u64; 8];
    unsafe {
        for i in 0..8 { key_512[i] = hw_rand64(); }
    }

    let phys_ring = boot::allocate_pages(AllocateType::AnyPages, MemoryType::RESERVED, 16384).map(|p| p.as_ptr() as u64).unwrap_or(0);
    uefi::system::with_stdout(|out| { let _ = out.reset(false); });
    uefi::system::with_stdout(|out| { let _ = out.output_string(uefi::cstr16!("=== ZERO-TIMING AUTONOMOUS RING 0 BOOT (UEFI) ===\r\n")); });

    let mut buf = [0u16; 19];
    unsafe {
        let misc = rdmsr(0x1A0);
        wrmsr(0x1A0, misc | (1u64 << 38));
        let pstate = rdmsr(0x198) & 0xFFFF;
        wrmsr(0x199, pstate);

        let (mut cpu_s, mut gpu_s, mut nvme_s) = (pstate ^ misc, 0x4750_5530u64, 0x4E56_4D45u64);
        for bus in 0..16u8 {
            for dev in 0..32u8 {
                let vd = pcie_read32(bus, dev, 0, 0x00);
                if (vd & 0xFFFF) != 0xFFFF {
                    let class = (pcie_read32(bus, dev, 0, 0x08) >> 24) & 0xFF;
                    let bar0 = pcie_read32(bus, dev, 0, 0x10) & 0xFFFF_FFF0;
                    if bar0 != 0 {
                        let sig = ((vd as u64) << 32) | (bar0 as u64);
                        if class == 0x01 { nvme_s ^= sig; }
                        else if class == 0x03 { gpu_s ^= sig; }
                        else if class == 0x02 { cpu_s = cpu_s.rotate_left(7) ^ sig; }
                    }
                }
            }
        }

        let triple_hw = cpu_s ^ gpu_s.rotate_left(13) ^ nvme_s.rotate_right(17);
        for i in 0..8 { key_512[i] ^= triple_hw.rotate_left((i * 8) as u32); }

        if phys_ring != 0 {
            let sealed_magic = 0x5A45_524F_5249_4E47u64 ^ key_512[0];
            asm!("movnti [{d}], {m}", "movnti [{d} + 8], {h}", "sfence", d = in(reg) phys_ring, m = in(reg) sealed_magic, h = in(reg) triple_hw, options(nostack));

            let diff = core::ptr::read_volatile((phys_ring + 8) as *const u64) ^ triple_hw;
            let ptr = phys_ring;
            let mut trap: u64 = 0;
            asm!("test {d}, {d}", "cmovnz {p}, {t}", "movnti [{p} + 16], {d}", "sfence", d = in(reg) diff, t = in(reg) (&mut trap as *mut u64) as u64, p = in(reg) ptr, options(nostack));

            uefi::system::with_stdout(|out| { let _ = out.output_string(uefi::cstr16!("[3-Way HW Seal] CPU+GPU+NVMe: ")); });
            to_hex16(triple_hw, 16, &mut buf);
            uefi::system::with_stdout(|out| { let _ = out.output_string(CStr16::from_u16_with_nul(&buf).unwrap()); });
            uefi::system::with_stdout(|out| { let _ = out.output_string(uefi::cstr16!(" (Autonomous RDRAND Mode)\r\n")); });
        }
    }

    boot::stall(1_000_000);
    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
