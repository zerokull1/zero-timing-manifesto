#![allow(dead_code)]

use core::arch::asm;

// Константы ядра Linux для AF_XDP Zero-Copy (include/uapi/linux/if_xdp.h)
const AF_XDP: usize = 44;
const SOCK_RAW: usize = 3;
const SOL_XDP: usize = 283;

const XDP_RX_RING: usize = 2;
const XDP_UMEM_REG: usize = 4;
const XDP_UMEM_FILL_RING: usize = 5;
const XDP_UMEM_COMPLETION_RING: usize = 6;

const XDP_PGOFF_RX_RING: isize = 0;
const XDP_UMEM_PGOFF_FILL_RING: isize = 0x100000000;

const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_COPY: u16 = 1 << 1;

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
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

#[inline(always)]
unsafe fn sys_socket(domain: usize, ty: usize, proto: usize) -> isize {
    let ret: isize;
    asm!("syscall", in("rax") 41usize, in("rdi") domain, in("rsi") ty, in("rdx") proto, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}

#[inline(always)]
unsafe fn sys_setsockopt(fd: usize, level: usize, optname: usize, optval: *const u8, optlen: usize) -> isize {
    let ret: isize;
    asm!("syscall", in("rax") 54usize, in("rdi") fd, in("rsi") level, in("rdx") optname, in("r10") optval, in("r8") optlen, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}

#[inline(always)]
unsafe fn sys_bind(fd: usize, addr: *const u8, addrlen: usize) -> isize {
    let ret: isize;
    asm!("syscall", in("rax") 49usize, in("rdi") fd, in("rsi") addr, in("rdx") addrlen, lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    ret
}

#[inline(always)]
unsafe fn sys_close(fd: usize) {
    asm!("syscall", in("rax") 3usize, in("rdi") fd, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
}

#[inline(always)]
unsafe fn sys_mmap_anon(size: usize) -> *mut u8 {
    let ret: *mut u8;
    asm!(
        "syscall",
        in("rax") 9usize,
        in("rdi") 0usize,
        in("rsi") size,
        in("rdx") 3usize,      // PROT_READ | PROT_WRITE
        in("r10") 0x22usize,   // MAP_PRIVATE | MAP_ANONYMOUS
        in("r8") -1isize,
        in("r9") 0usize,
        lateout("rax") ret,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Инициализирует AF_XDP сокет и регистрирует 256 КБ Zero-Copy UMEM буфер (64 чанка по 4096 байт)
/// Возвращает (fd_сокета, указатель_на_UMEM) или отрицательный код ошибки ядра.
pub unsafe fn init_af_xdp_umem_socket(ifindex: u32, queue_id: u32) -> (isize, *mut u8) {
    let fd = sys_socket(AF_XDP, SOCK_RAW, 0);
    if fd < 0 {
        return (fd, core::ptr::null_mut());
    }

    let umem_size = 64 * 4096;
    let umem_ptr = sys_mmap_anon(umem_size);
    if (umem_ptr as isize) < 0 {
        sys_close(fd as usize);
        return (-12, core::ptr::null_mut());
    }

    let reg = XdpUmemReg {
        addr: umem_ptr as u64,
        len: umem_size as u64,
        chunk_size: 4096,
        headroom: 0,
        flags: 0,
    };

    let rc = sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_REG, &reg as *const _ as *const u8, core::mem::size_of::<XdpUmemReg>());
    if rc < 0 {
        sys_close(fd as usize);
        return (rc, core::ptr::null_mut());
    }

    let ring_size: u32 = 64;
    let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size as *const _ as *const u8, 4);
    let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size as *const _ as *const u8, 4);
    let _ = sys_setsockopt(fd as usize, SOL_XDP, XDP_RX_RING, &ring_size as *const _ as *const u8, 4);

    if ifindex > 0 {
        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: XDP_COPY, // Автоматически работает и на veth, и на физических NIC
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let brc = sys_bind(fd as usize, &sxdp as *const _ as *const u8, core::mem::size_of::<SockaddrXdp>());
        if brc < 0 {
            sys_close(fd as usize);
            return (brc, core::ptr::null_mut());
        }
    }

    (fd, umem_ptr)
}

/// Проверка инициализации AF_XDP UMEM буфера в ядре Linux
pub fn verify_af_xdp_subsystem(ifindex: u32) -> (isize, usize) {
    unsafe {
        let (fd, ptr) = init_af_xdp_umem_socket(ifindex, 0);
        if fd >= 0 {
            sys_close(fd as usize);
        }
        (fd, ptr as usize)
    }
}
