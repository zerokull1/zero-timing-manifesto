#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: usize = 1;
const SYS_MMAP: usize = 9;
const SYS_EXIT: usize = 60;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CREATE1: usize = 291;
const SYS_BPF: usize = 321;

const BPF_MAP_LOOKUP_ELEM: usize = 1;
const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_MAP_DELETE_ELEM: usize = 3;
const BPF_OBJ_GET: usize = 7;

const PATH_WHITELIST: &[u8] = b"/sys/fs/bpf/zero_shield/whitelist_v4\0";
const PATH_BLACKLIST: &[u8] = b"/sys/fs/bpf/zero_shield/blacklist_v4\0";
const PATH_CONFIG: &[u8] = b"/sys/fs/bpf/zero_shield/config_map\0";
const PATH_STATS: &[u8] = b"/sys/fs/bpf/zero_shield/stats_map\0";
const PATH_RING: &[u8] = b"/sys/fs/bpf/zero_shield/events_ring\0";
const RING_SIZE: usize = 4096 * 16;

#[repr(C)]
struct BpfMapElemAttr { map_fd: u32, _pad: u32, key: u64, value: u64, flags: u64 }

#[repr(C)]
struct BpfObjAttr { pathname: u64, bpf_fd: u32, file_flags: u32 }

#[repr(C)]
#[derive(Copy, Clone)]
struct ShieldConfig { mode: u32, block_ttl_65: u32, block_ttl_129: u32, pps_limit: u32 }

#[repr(C)]
#[derive(Copy, Clone)]
struct DataRec { rx_packets: u64, dropped_packets: u64, whitelisted_packets: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
struct AlertEvent { timestamp_ns: u64, src_ip: u32, reason: u32 }

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct EpollEvent { events: u32, data: u64 }

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void {
    let mut i = 0;
    unsafe { while i < n { core::ptr::write_volatile((s as *mut u8).add(i), c as u8); i += 1; } }
    s
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const i8) -> usize {
    let mut len = 0;
    unsafe { while core::ptr::read_volatile((s as *const u8).add(len)) != 0 { len += 1; } }
    len
}

#[inline(always)]
unsafe fn syscall3(num: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") num, in("rdi") a1, in("rsi") a2, in("rdx") a3,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn syscall4(num: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") num, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn sys_mmap(len: usize, prot: usize, flags: usize, fd: usize, off: usize) -> *mut u8 {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") SYS_MMAP, in("rdi") 0usize, in("rsi") len, in("rdx") prot,
             in("r10") flags, in("r8") fd, in("r9") off,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret as *mut u8
}

#[inline(always)]
unsafe fn sys_write(fd: usize, buf: &[u8]) {
    unsafe { let _ = syscall3(SYS_WRITE, fd, buf.as_ptr() as usize, buf.len()); }
}

#[inline(always)]
unsafe fn sys_exit(code: usize) -> ! {
    unsafe { asm!("syscall", in("rax") SYS_EXIT, in("rdi") code, options(noreturn)); }
}

unsafe fn bpf_obj_get(path: &[u8]) -> isize {
    let attr = BpfObjAttr { pathname: path.as_ptr() as u64, bpf_fd: 0, file_flags: 0 };
    unsafe { syscall3(SYS_BPF, BPF_OBJ_GET, &attr as *const BpfObjAttr as usize, core::mem::size_of::<BpfObjAttr>()) }
}

unsafe fn cstr_to_slice<'a>(ptr: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(ptr, strlen(ptr as *const i8)) }
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() { return None; }
    let mut acc: u64 = 0;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        acc = acc * 10 + (b - b'0') as u64;
        if acc > u32::MAX as u64 { return None; }
    }
    Some(acc as u32)
}

fn parse_ipv4_be(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut idx = 0;
    let mut acc: u16 = 0;
    let mut has_digit = false;
    for &b in s {
        if b >= b'0' && b <= b'9' {
            acc = acc * 10 + (b - b'0') as u16;
            if acc > 255 { return None; }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || idx >= 3 { return None; }
            octets[idx] = acc as u8;
            idx += 1;
            acc = 0;
            has_digit = false;
        } else { return None; }
    }
    if !has_digit || idx != 3 { return None; }
    octets[3] = acc as u8;
    Some(u32::from_ne_bytes(octets))
}

unsafe fn write_u64(mut n: u64) {
    let mut buf = [0u8; 20];
    if n == 0 { unsafe { sys_write(1, b"0"); } return; }
    let mut i = 20;
    while n > 0 { i -= 1; buf[i] = b'0' + (n % 10) as u8; n /= 10; }
    unsafe { sys_write(1, &buf[i..]); }
}

unsafe fn write_ipv4_be(ip_be: u32) {
    let b = ip_be.to_ne_bytes();
    unsafe {
        write_u64(b[0] as u64); sys_write(1, b".");
        write_u64(b[1] as u64); sys_write(1, b".");
        write_u64(b[2] as u64); sys_write(1, b".");
        write_u64(b[3] as u64);
    }
}

unsafe fn run_watch() -> ! {
    unsafe {
        let fd = bpf_obj_get(PATH_RING);
        if fd < 0 { sys_write(2, b"[ERR] Cannot open events_ring\n"); sys_exit(1); }
        let cons_ptr = sys_mmap(4096, 3, 1, fd as usize, 0);
        let prod_ptr = sys_mmap(4096 + 2 * RING_SIZE, 1, 1, fd as usize, 4096);
        let epfd = syscall3(291, 0, 0, 0);
        let mut ev = EpollEvent { events: 1, data: fd as u64 };
        let _ = syscall4(SYS_EPOLL_CTL, epfd as usize, 1, fd as usize, &mut ev as *mut EpollEvent as usize);

        sys_write(1, b"[OK] no_std Rust Sentinel sleeping on epoll_wait (0% CPU)...\n");
        let mask = (RING_SIZE - 1) as u64;
        let mut out_ev = EpollEvent { events: 0, data: 0 };

        loop {
            let _ = syscall4(SYS_EPOLL_WAIT, epfd as usize, &mut out_ev as *mut EpollEvent as usize, 1, usize::MAX);
            let mut cons = core::ptr::read_volatile(cons_ptr as *const u64);
            let prod = core::ptr::read_volatile(prod_ptr as *const u64);
            while cons < prod {
                let off = 4096 + ((cons & mask) as usize);
                let rec_len = core::ptr::read_volatile(prod_ptr.add(off) as *const u32);
                if (rec_len & (1 << 31)) != 0 { break; }
                let aligned = ((rec_len + 7) & !7) as u64;
                if (rec_len & (1 << 30)) == 0 {
                    let alert = core::ptr::read_volatile(prod_ptr.add(off + 8) as *const AlertEvent);
                    sys_write(1, b"[ALERT] SRC="); write_ipv4_be(alert.src_ip);
                    match alert.reason { 2 => sys_write(1, b" | RATE_FLOOD\n"), 3 => sys_write(1, b" | TCP_SCAN\n"), _ => sys_write(1, b" | TTL_ANOMALY\n") }
                }
                cons += 8 + aligned;
                core::ptr::write_volatile(cons_ptr as *mut u64, cons);
            }
        }
    }
}

fn print_usage() {
    unsafe { sys_write(1, b"Usage:\n  zero-ctl stats\n  zero-ctl watch\n  zero-ctl allow <IPv4>\n  zero-ctl deny <IPv4>\n  zero-ctl ban <IPv4>\n  zero-ctl unban <IPv4>\n  zero-ctl limit <pps>\n  zero-ctl mode <fail-open|monitor|enforce>\n"); }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mov rdi, rsp", "and rsp, -16", "jmp {entry}", entry = sym rust_main);
}

unsafe extern "C" fn rust_main(stack_ptr: *const usize) -> ! {
    unsafe {
        let argc = *stack_ptr;
        let argv = stack_ptr.add(1) as *const *const u8;
        if argc < 2 { print_usage(); sys_exit(1); }
        let cmd = cstr_to_slice(*argv.add(1));

        if cmd == b"watch" { run_watch(); }
        if cmd == b"stats" {
            let fd = bpf_obj_get(PATH_STATS);
            if fd < 0 { sys_write(2, b"[ERR] Cannot open stats_map\n"); sys_exit(1); }
            let key: u32 = 0;
            let mut per_cpu = [DataRec { rx_packets: 0, dropped_packets: 0, whitelisted_packets: 0 }; 64];
            let attr = BpfMapElemAttr { map_fd: fd as u32, _pad: 0, key: &key as *const u32 as u64, value: per_cpu.as_mut_ptr() as u64, flags: 0 };
            if syscall3(SYS_BPF, BPF_MAP_LOOKUP_ELEM, &attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>()) != 0 {
                sys_write(2, b"[ERR] Failed to read stats_map\n"); sys_exit(1);
            }
            let (mut rx, mut drop, mut wl) = (0u64, 0u64, 0u64);
            for rec in &per_cpu { rx = rx.wrapping_add(rec.rx_packets); drop = drop.wrapping_add(rec.dropped_packets); wl = wl.wrapping_add(rec.whitelisted_packets); }
            sys_write(1, b"RX        : "); write_u64(rx); sys_write(1, b"\nDROP      : "); write_u64(drop); sys_write(1, b"\nWHITELIST : "); write_u64(wl); sys_write(1, b"\n");
            sys_exit(0);
        }

        if argc < 3 { print_usage(); sys_exit(1); }
        let arg = cstr_to_slice(*argv.add(2));

        if cmd == b"allow" || cmd == b"deny" || cmd == b"ban" || cmd == b"unban" {
            let is_black = cmd == b"ban" || cmd == b"unban";
            let is_add = cmd == b"allow" || cmd == b"ban";
            let ip_be = match parse_ipv4_be(arg) { Some(v) => v, None => { sys_write(2, b"[ERR] Invalid IPv4\n"); sys_exit(1); } };
            let fd = bpf_obj_get(if is_black { PATH_BLACKLIST } else { PATH_WHITELIST });
            if fd < 0 { sys_write(2, b"[ERR] Cannot open BPF map\n"); sys_exit(1); }
            let val: u8 = 1;
            let attr = BpfMapElemAttr { map_fd: fd as u32, _pad: 0, key: &ip_be as *const u32 as u64, value: if is_add { &val as *const u8 as u64 } else { 0 }, flags: 0 };
            let op = if is_add { BPF_MAP_UPDATE_ELEM } else { BPF_MAP_DELETE_ELEM };
            if syscall3(SYS_BPF, op, &attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>()) == 0 {
                sys_write(1, b"[OK] List updated\n"); sys_exit(0);
            }
            sys_write(2, b"[ERR] BPF update failed\n"); sys_exit(1);
        } else if false {
            let ip_be = match parse_ipv4_be(arg) { Some(v) => v, None => { sys_write(2, b"[ERR] Invalid IPv4\n"); sys_exit(1); } };
            let fd = bpf_obj_get(PATH_WHITELIST);
            if fd < 0 { sys_write(2, b"[ERR] Cannot open whitelist_v4\n"); sys_exit(1); }
            let allow: u8 = 1;
            let attr = BpfMapElemAttr { map_fd: fd as u32, _pad: 0, key: &ip_be as *const u32 as u64, value: if cmd == b"allow" { &allow as *const u8 as u64 } else { 0 }, flags: 0 };
            let op = if cmd == b"allow" { BPF_MAP_UPDATE_ELEM } else { BPF_MAP_DELETE_ELEM };
            if syscall3(SYS_BPF, op, &attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>()) == 0 {
                sys_write(1, b"[OK] Whitelist updated\n"); sys_exit(0);
            }
            sys_write(2, b"[ERR] BPF update failed\n"); sys_exit(1);
        } else if cmd == b"mode" || cmd == b"limit" {
            let fd = bpf_obj_get(PATH_CONFIG);
            if fd < 0 { sys_write(2, b"[ERR] Cannot open config_map\n"); sys_exit(1); }
            let key: u32 = 0;
            let mut cfg = ShieldConfig { mode: 2, block_ttl_65: 1, block_ttl_129: 1, pps_limit: 0 };
            let get_attr = BpfMapElemAttr { map_fd: fd as u32, _pad: 0, key: &key as *const u32 as u64, value: &mut cfg as *mut ShieldConfig as u64, flags: 0 };
            let _ = syscall3(SYS_BPF, BPF_MAP_LOOKUP_ELEM, &get_attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>());
            if cmd == b"mode" {
                cfg.mode = if arg == b"fail-open" { 0 } else if arg == b"monitor" { 1 } else if arg == b"enforce" { 2 } else { print_usage(); sys_exit(1); };
            } else {
                cfg.pps_limit = match parse_u32(arg) { Some(v) => v, None => { sys_write(2, b"[ERR] Invalid PPS\n"); sys_exit(1); } };
            }
            let put_attr = BpfMapElemAttr { map_fd: fd as u32, _pad: 0, key: &key as *const u32 as u64, value: &cfg as *const ShieldConfig as u64, flags: 0 };
            if syscall3(SYS_BPF, BPF_MAP_UPDATE_ELEM, &put_attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>()) == 0 {
                sys_write(1, b"[OK] Config updated\n"); sys_exit(0);
            }
            sys_write(2, b"[ERR] Config update failed\n"); sys_exit(1);
        } else { print_usage(); sys_exit(1); }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { unsafe { sys_exit(1) } }
