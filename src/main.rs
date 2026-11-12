#![no_std]
#![no_main]

mod tsc;
mod core_engine;
mod entropy_cpu;
mod smp_stress;
mod l7_shield;
mod af_xdp_engine;
mod nic_bar0_pmd;
mod ring_abi;
mod flow_table;
mod arch_hal;
mod thin_hypervisor;

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sys_exit(1);
}

#[inline(always)]
fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 1usize, in("rdi") fd, in("rsi") buf, in("rdx") len, out("rcx") _, out("r11") _, options(nostack));
    }
}

#[inline(always)]
fn sys_openat(dfd: isize, path: *const u8, flags: usize, mode: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") 257usize, in("rdi") dfd, in("rsi") path, in("rdx") flags, in("r10") mode, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
fn sys_ftruncate(fd: isize, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 77usize, in("rdi") fd, in("rsi") len, out("rcx") _, out("r11") _, options(nostack));
    }
}

#[inline(always)]
fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, offset: usize) -> *mut u8 {
    let ret: *mut u8;
    unsafe {
        asm!("syscall", in("rax") 9usize, in("rdi") addr, in("rsi") len, in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") offset, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60usize, in("rdi") code, options(noreturn, nostack));
    }
}

fn print_str(s: &str) { sys_write(1, s.as_ptr(), s.len()); }

fn print_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if n == 0 { print_str("0"); return; }
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    sys_write(1, buf[i..].as_ptr(), 20 - i);
}

fn print_hex8(val: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let buf = [b'0', b'x', HEX[((val >> 4) & 0xF) as usize], HEX[(val & 0xF) as usize]];
    sys_write(1, buf.as_ptr(), 4);
}

#[no_mangle]
pub extern "C" fn main_entry() -> ! {
    let (anomaly_cycles, clean_cycles, mask, fixed_flags) =
        core_engine::simulate_shield_rack_benchmark();

    print_str("[Rack-Scale Shield + GPU IAT Offload]\n");
    print_str("  1. Phase 2/3 Bypass Blocked: "); print_u64(anomaly_cycles); print_str(" CPU cycles\n");
    print_str("  2. Phase 1 Clean Fast-Path:  "); print_u64(clean_cycles); print_str(" CPU cycles\n");
    print_str("  3. Active Shield Mask: "); print_hex8(mask);
    print_str(" | TCP Flags: "); print_hex8(fixed_flags); print_str("\n");

    // Открываем /dev/shm/zero_shield_ring (O_RDWR | O_CREAT = 0x42, mode 0666)
    let shm_path = b"/dev/shm/zero_shield_ring\0";
    let fd = sys_openat(-100, shm_path.as_ptr(), 0x42, 0o666);
    if fd >= 0 {
        sys_ftruncate(fd, 4096);
        // PROT_READ | PROT_WRITE = 3, MAP_SHARED = 1
        let shm_ptr = sys_mmap(0, 4096, 3, 1, fd, 0);
        if (shm_ptr as isize) > 0 {
            let ring_ptr = shm_ptr as *mut u64;
            let mut base_tsc = tsc::rdtsc_start();
            let mut i = 0usize;
            while i < 256 {
                // Внедряем 4 реальных аномальных скачка IAT для проверки GPU-фильтра
                let step = if i == 15 || i == 77 || i == 140 || i == 220 { 12000 } else { 65 };
                base_tsc += step;
                unsafe {
                    asm!("movnti [{dst}], {val}", dst = in(reg) ring_ptr.add(i), val = in(reg) base_tsc, options(nostack));
                }
                i += 1;
            }
            unsafe { asm!("sfence", options(nostack)); }
            let (cpu_alerts, cpu_h) = entropy_cpu::analyze_ddr_ring_cpu(ring_ptr);
            print_str("  4. Rack CPU Worker (No-GPU Mode): Jitter=");
            print_u64(cpu_alerts as u64);
            print_str(" | Entropy=");
            print_u64((cpu_h / 100) as u64);
            print_str(".");
            let frac = cpu_h % 100;
            if frac < 10 { print_str("0"); }
            print_u64(frac as u64);
            print_str(" bits\n");
        }
    }

    let (total_pkts, smp_cycles) = smp_stress::run_smp_matrix_stress(4);
    print_str("  5. SMP Matrix Stress (4 Cores, Zero False-Sharing): ");
    print_u64(total_pkts);
    print_str(" pkts in ");
    print_u64(smp_cycles);
    print_str(" cycles (~");
    let ns_per_pkt = if total_pkts > 0 { (smp_cycles * 100) / (total_pkts * 35) } else { 0 };
    print_u64(ns_per_pkt / 10);
    print_str(".");
    print_u64(ns_per_pkt % 10);
    print_str(" ns/pkt aggregate)\n");
    let (l7_cycles, l7_verdict) = l7_shield::benchmark_l7_swar();
    print_str("  6. Branchless x86_64 ASM L7 DPI (TLS + HTTP): ");
    print_u64(l7_cycles);
    print_str(" cycles | Verdict Mask: ");
    print_hex8(l7_verdict);
    print_str("\n");
    print_str("\n");
    let map_fd = unsafe { af_xdp_engine::open_pinned_xsk_map() };
    let (xsk_fd, umem_addr, rx_len, rx_verdict) = af_xdp_engine::run_live_xdp_zerocopy_rx(0, map_fd);
    print_str("  7. AF_XDP Zero-Copy UMEM Subsystem: ");
    if xsk_fd >= 0 {
        print_str("ONLINE (fd=");
        print_u64(xsk_fd as u64);
        print_str(", UMEM=256KB @ 0x");
        let mut shift = 56i32;
        while shift >= 0 {
            let b = ((umem_addr as u64 >> shift) & 0xFF) as u8;
            let hi = b >> 4;
            let lo = b & 0x0F;
            let c1 = if hi < 10 { b'0' + hi } else { b'A' + (hi - 10) };
            let c2 = if lo < 10 { b'0' + lo } else { b'A' + (lo - 10) };
            let pair = [c1, c2];
            sys_write(1, pair.as_ptr(), 2);
            shift -= 8;
        }
        print_str(", RX_LEN="); print_u64(rx_len as u64); print_str(", ASM_L7_VERDICT="); print_hex8(rx_verdict); print_str(")\n");
    } else {
        print_str("ERR=");
        print_u64((-xsk_fd) as u64);
        print_str("\n");
    }
    sys_exit(0);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("and rsp, -16", "call main_entry");
}
