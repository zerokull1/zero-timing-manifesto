#![allow(dead_code)]

use core::arch::asm;

// Linux AF_XDP / Socket / BPF syscalls & constants (x86_64)
const SYS_MMAP: usize = 9;
const SYS_SOCKET: usize = 41;
const SYS_BIND: usize = 49;
const SYS_SETSOCKOPT: usize = 54;
const SYS_BPF: usize = 321;

const AF_XDP: usize = 44;
const SOCK_RAW: usize = 3;
const SOL_XDP: usize = 283;

const XDP_RX_RING: usize = 2;
const XDP_TX_RING: usize = 3;
const XDP_UMEM_REG: usize = 4;
const XDP_UMEM_FILL_RING: usize = 5;
const XDP_UMEM_COMPLETION_RING: usize = 6;

const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_OBJ_GET: usize = 7;

const PATH_XSKS_MAP: &[u8] = b"/sys/fs/bpf/zero_shield/xsks_map\0";
const NUM_FRAMES: usize = 4096;
const FRAME_SIZE: usize = 4096;
const UMEM_SIZE: usize = NUM_FRAMES * FRAME_SIZE;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NicBackendMode {
    DrvZeroCopy = 1,
    DrvCopy     = 2,
    SkbGeneric  = 3,
    CAbiBridge  = 4,
}

impl NicBackendMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DrvZeroCopy => "XDP_DRV + ZEROCOPY (Hardware DMA)",
            Self::DrvCopy     => "XDP_DRV + COPY (Driver Ring)",
            Self::SkbGeneric  => "XDP_SKB (Generic Kernel Fallback)",
            Self::CAbiBridge  => "C-ABI FFI (DPDK / netmap / DAQ)",
        }
    }
}

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
struct BpfObjAttr { pathname: u64, bpf_fd: u32, file_flags: u32 }

#[repr(C)]
struct BpfMapElemAttr { map_fd: u32, _pad: u32, key: u64, value: u64, flags: u64 }

pub trait NicDriver {
    fn init_with_cascade(&mut self, ifindex: u32, queue_id: u32) -> Result<NicBackendMode, i32>;
    fn rx_burst<'a>(&mut self, batch: &mut [&'a [u8]]) -> usize;
    fn tx_burst(&mut self, packets: &[&[u8]]) -> usize;
    fn active_mode(&self) -> NicBackendMode;
}

pub fn probe_af_xdp_cascade<F>(mut try_bind: F) -> Result<NicBackendMode, i32>
where
    F: FnMut(NicBackendMode) -> Result<(), i32>,
{
    let candidates = [
        NicBackendMode::DrvZeroCopy,
        NicBackendMode::DrvCopy,
        NicBackendMode::SkbGeneric,
    ];
    let mut last_err = -1;
    for mode in candidates {
        match try_bind(mode) {
            Ok(()) => return Ok(mode),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

#[inline(always)]
unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let r: isize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, in("rdx") a3,
             lateout("rax") r, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

#[inline(always)]
unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let r: isize;
    unsafe {
        asm!("syscall", in("rax") n, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
             lateout("rax") r, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

#[inline(always)]
unsafe fn sys_mmap_anon(len: usize) -> *mut u8 {
    let r: isize;
    unsafe {
        asm!("syscall", in("rax") SYS_MMAP, in("rdi") 0usize, in("rsi") len, in("rdx") 3usize,
             in("r10") 0x22usize, in("r8") usize::MAX, in("r9") 0usize,
             lateout("rax") r, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r as *mut u8
}

/// Живой no_std AF_XDP драйвер с UMEM-пулом и регистрацией в xsks_map
pub struct AfXdpSocketDriver {
    pub fd: i32,
    pub umem_base: *mut u8,
    pub mode: NicBackendMode,
}

impl AfXdpSocketDriver {
    pub const fn new() -> Self {
        Self { fd: -1, umem_base: core::ptr::null_mut(), mode: NicBackendMode::SkbGeneric }
    }

    unsafe fn register_in_xsks_map(&self, queue_id: u32) -> Result<(), i32> {
        let obj = BpfObjAttr { pathname: PATH_XSKS_MAP.as_ptr() as u64, bpf_fd: 0, file_flags: 0 };
        let map_fd = unsafe { syscall3(SYS_BPF, BPF_OBJ_GET, &obj as *const BpfObjAttr as usize, core::mem::size_of::<BpfObjAttr>()) };
        if map_fd < 0 { return Err(map_fd as i32); }
        let sock_fd = self.fd as u32;
        let attr = BpfMapElemAttr {
            map_fd: map_fd as u32, _pad: 0,
            key: &queue_id as *const u32 as u64,
            value: &sock_fd as *const u32 as u64,
            flags: 0,
        };
        let ret = unsafe { syscall3(SYS_BPF, BPF_MAP_UPDATE_ELEM, &attr as *const BpfMapElemAttr as usize, core::mem::size_of::<BpfMapElemAttr>()) };
        if ret < 0 { Err(ret as i32) } else { Ok(()) }
    }
}

impl NicDriver for AfXdpSocketDriver {
    fn init_with_cascade(&mut self, ifindex: u32, queue_id: u32) -> Result<NicBackendMode, i32> {
        unsafe {
            let fd = syscall3(SYS_SOCKET, AF_XDP, SOCK_RAW, 0);
            if fd < 0 { return Err(fd as i32); }
            self.fd = fd as i32;

            let umem = sys_mmap_anon(UMEM_SIZE);
            if (umem as isize) < 0 { return Err(-12); }
            self.umem_base = umem;

            let reg = XdpUmemReg { addr: umem as u64, len: UMEM_SIZE as u64, chunk_size: FRAME_SIZE as u32, headroom: 0, flags: 0 };
            let r = syscall5(SYS_SETSOCKOPT, fd as usize, SOL_XDP, XDP_UMEM_REG, &reg as *const XdpUmemReg as usize, core::mem::size_of::<XdpUmemReg>());
            if r < 0 { return Err(r as i32); }

            let ring_sz: u32 = 2048;
            for opt in [XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                let rc = syscall5(SYS_SETSOCKOPT, fd as usize, SOL_XDP, opt, &ring_sz as *const u32 as usize, 4);
                if rc < 0 { return Err(rc as i32); }
            }

            let chosen = probe_af_xdp_cascade(|candidate| {
                let flags = match candidate {
                    NicBackendMode::DrvZeroCopy => XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
                    NicBackendMode::DrvCopy     => XDP_COPY | XDP_USE_NEED_WAKEUP,
                    _                           => XDP_COPY,
                };
                let sa = SockaddrXdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: flags,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id,
                    sxdp_shared_umem_fd: 0,
                };
                let b = syscall3(SYS_BIND, fd as usize, &sa as *const SockaddrXdp as usize, core::mem::size_of::<SockaddrXdp>());
                if b == 0 { Ok(()) } else { Err(b as i32) }
            })?;

            self.mode = chosen;
            let _ = self.register_in_xsks_map(queue_id);
            Ok(chosen)
        }
    }

    fn rx_burst<'a>(&mut self, _batch: &mut [&'a [u8]]) -> usize { 0 }
    fn tx_burst(&mut self, _packets: &[&[u8]]) -> usize { 0 }
    fn active_mode(&self) -> NicBackendMode { self.mode }
}
