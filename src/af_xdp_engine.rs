#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{fence, Ordering};

const AF_XDP: usize = 44;
const SOCK_RAW: usize = 3;
const SOL_XDP: usize = 283;

const XDP_RX_RING: usize = 2;
const XDP_UMEM_REG: usize = 4;
const XDP_UMEM_FILL_RING: usize = 5;
const XDP_UMEM_COMPLETION_RING: usize = 6;
const XDP_MMAP_OFFSETS: usize = 7;

const XDP_PGOFF_RX_RING: isize = 0;
const XDP_UMEM_PGOFF_FILL_RING: isize = 0x100000000;
const XDP_COPY: u16 = 1 << 1;

const BPF_MAP_UPDATE_ELEM: usize = 2;

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,
    cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[repr(C)]
union BpfAttrMapElem {
    map_elem: BpfMapElemStruct,
    _pad: [u64; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BpfMapElemStruct {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[inline(always)]
unsafe fn sys_socket(domain: usize, ty: usize, proto: usize) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 41usize, in("rdi") domain, in("rsi") ty, in("rdx") proto, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

#[inline(always)]
unsafe fn sys_setsockopt(fd: usize, level: usize, optname: usize, optval: *const u8, optlen: usize) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 54usize, in("rdi") fd, in("rsi") level, in("rdx") optname, in("r10") optval, in("r8") optlen, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

#[inline(always)]
unsafe fn sys_getsockopt(fd: usize, level: usize, optname: usize, optval: *mut u8, optlen: *mut u32) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 55usize, in("rdi") fd, in("rsi") level, in("rdx") optname, in("r10") optval, in("r8") optlen, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

#[inline(always)]
unsafe fn sys_bind(fd: usize, addr: *const u8, addrlen: usize) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 49usize, in("rdi") fd, in("rsi") addr, in("rdx") addrlen, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

#[inline(always)]
unsafe fn sys_bpf(cmd: usize, attr: *const BpfAttrMapElem, size: usize) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 321usize, in("rdi") cmd, in("rsi") attr, in("rdx") size, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

#[inline(always)]
unsafe fn sys_close(fd: usize) { unsafe {
    asm!("syscall", in("rax") 3usize, in("rdi") fd, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
}}

#[inline(always)]
unsafe fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: isize, offset: isize) -> *mut u8 { unsafe {
    let ret: *mut u8;
    asm!(
        "syscall",
        in("rax") 9usize,
        in("rdi") addr,
        in("rsi") len,
        in("rdx") prot,
        in("r10") flags,
        in("r8") fd,
        in("r9") offset,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}}

/// Запускает полный цикл Zero-Copy приёма: Fill Ring -> XSKMAP -> Rx Ring -> ASM L7 DPI
pub fn run_live_xdp_zerocopy_rx(ifindex: u32, xsk_map_fd: i32) -> (isize, usize, u32, u8) {
    unsafe {
        let fd = sys_socket(AF_XDP, SOCK_RAW, 0);
        if fd < 0 {
            return (fd, 0, 0, 0);
        }

        let umem_size = 64 * 4096;
        let umem_ptr = sys_mmap(0, umem_size, 3, 0x22, -1, 0);
        if (umem_ptr as isize) < 0 {
            sys_close(fd as usize);
            return (-12, 0, 0, 0);
        }

        let reg = XdpUmemReg { addr: umem_ptr as u64, len: umem_size as u64, chunk_size: 4096, headroom: 0, flags: 0 };
        if sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_REG, &reg as *const _ as *const u8, core::mem::size_of::<XdpUmemReg>()) < 0 {
            sys_close(fd as usize);
            return (-22, 0, 0, 0);
        }

        let ring_size: u32 = 64;
        let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size as *const _ as *const u8, 4);
        let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size as *const _ as *const u8, 4);
        let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_RX_RING, &ring_size as *const _ as *const u8, 4);

        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = core::mem::size_of::<XdpMmapOffsets>() as u32;
        if sys_getsockopt(fd as usize, SOL_XDP, XDP_MMAP_OFFSETS, &mut offsets as *mut _ as *mut u8, &mut optlen) < 0 {
            sys_close(fd as usize);
            return (-95, 0, 0, 0);
        }

        // Маппим Fill Ring и загружаем 32 свободных чанка UMEM для ядра
        let fr_map_len = offsets.fr.desc as usize + 64 * 8;
        let fr_base = sys_mmap(0, fr_map_len, 3, 0x01 | 0x8000, fd, XDP_UMEM_PGOFF_FILL_RING);
        let fr_prod = fr_base.add(offsets.fr.producer as usize) as *mut u32;
        let fr_desc = fr_base.add(offsets.fr.desc as usize) as *mut u64;

        for i in 0..32u32 {
            core::ptr::write_volatile(fr_desc.add(i as usize), (i as u64) * 4096);
        }
        fence(Ordering::Release);
        core::ptr::write_volatile(fr_prod, 32);

        // Маппим Rx Ring для чтения входящих кадров без копирования
        let rx_map_len = offsets.rx.desc as usize + 64 * core::mem::size_of::<XdpDesc>();
        let rx_base = sys_mmap(0, rx_map_len, 3, 0x01 | 0x8000, fd, XDP_PGOFF_RX_RING);
        let rx_prod = rx_base.add(offsets.rx.producer as usize) as *const u32;
        let rx_cons = rx_base.add(offsets.rx.consumer as usize) as *mut u32;
        let rx_desc = rx_base.add(offsets.rx.desc as usize) as *const XdpDesc;

        if ifindex > 0 {
            let sxdp = SockaddrXdp {
                sxdp_family: AF_XDP as u16,
                sxdp_flags: XDP_COPY,
                sxdp_ifindex: ifindex,
                sxdp_queue_id: 0,
                sxdp_shared_umem_fd: 0,
            };
            if sys_bind(fd as usize, &sxdp as *const _ as *const u8, core::mem::size_of::<SockaddrXdp>()) < 0 {
                sys_close(fd as usize);
                return (-19, umem_ptr as usize, 0, 0);
            }
        }

        // Регистрируем дескриптор сокета в ядерной карте xsks_map[0]
        if xsk_map_fd >= 0 {
            let key: u32 = 0;
            let val: u32 = fd as u32;
            let attr = BpfAttrMapElem {
                map_elem: BpfMapElemStruct {
                    map_fd: xsk_map_fd as u32,
                    _pad0: 0,
                    key: &key as *const _ as u64,
                    value: &val as *const _ as u64,
                    flags: 0,
                },
            };
            let _ = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, core::mem::size_of::<BpfAttrMapElem>());
        }

        // Ждём поступления пакета в UMEM (до ~1.5 сек спин-ожидания при активном XSKMAP)
        let mut rx_len = 0u32;
        let mut l7_verdict = 0u8;
        if xsk_map_fd >= 0 {
            let mut pfd = PollFd { fd: fd as i32, events: 1, revents: 0 };
            let _ = sys_poll(&mut pfd, 1, 800);
            let mut spins = 0u64;
            while spins < 80_000_000 {
                let prod_idx = core::ptr::read_volatile(rx_prod);
                let cons_idx = core::ptr::read_volatile(rx_cons);
                if prod_idx != cons_idx {
                    fence(Ordering::Acquire);
                    let desc = core::ptr::read_volatile(rx_desc.add((cons_idx & 63) as usize));
                    rx_len = desc.len;
                    // Передаём указатель на L7 TCP Payload (смещение 14 Eth + 20 IP + 20 TCP = 54 байта) в ASM L7 DPI
                    if rx_len >= 70 {
                        let payload_ptr = umem_ptr.add(desc.addr as usize + 54);
                        let v = crate::l7_shield::inspect_l7_payload_asm(payload_ptr, (rx_len - 54) as usize, 80);
                        l7_verdict = v as u8;
                    }
                    core::ptr::write_volatile(rx_cons, cons_idx.wrapping_add(1));
                    break;
                }
                core::hint::spin_loop();
                spins += 1;
            }
        }

        sys_close(fd as usize);
        (fd, umem_ptr as usize, rx_len, l7_verdict)
    }
}

#[repr(C)]
union BpfAttrObj {
    obj: BpfObjStruct,
    _pad: [u64; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BpfObjStruct {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[inline(always)]
unsafe fn sys_poll(fds: *mut PollFd, nfds: usize, timeout_ms: i32) -> isize { unsafe {
    let ret: isize;
    asm!("syscall", in("rax") 7usize, in("rdi") fds, in("rsi") nfds, in("rdx") timeout_ms, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}}

pub unsafe fn open_pinned_xsk_map() -> i32 { unsafe {
    let path = b"/sys/fs/bpf/zero_xsk_map\0";
    let attr = BpfAttrObj {
        obj: BpfObjStruct {
            pathname: path.as_ptr() as u64,
            bpf_fd: 0,
            file_flags: 0,
        },
    };
    let fd: isize;
    asm!("syscall", in("rax") 321usize, in("rdi") 7usize, in("rsi") &attr, in("rdx") core::mem::size_of::<BpfAttrObj>(), lateout("rax") fd, out("rcx") _, out("r11") _, options(nostack));
    fd as i32
}}

pub fn verify_af_xdp_subsystem(ifindex: u32) -> (isize, usize) {
    let (fd, ptr, _, _) = run_live_xdp_zerocopy_rx(ifindex, -1);
    (fd, ptr)
}
