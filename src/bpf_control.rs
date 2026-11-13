//! Zero-dependency `no_std` Linux eBPF map controller via raw `SYS_bpf` syscall.
//! Allows hot-reloading IPv4 whitelists and Fail-Open/Enforce modes without recompilation.

use core::arch::asm;

const SYS_BPF: usize = 321;
const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_MAP_DELETE_ELEM: usize = 3;
const BPF_OBJ_GET: usize = 7;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShieldMode {
    FailOpen = 0,
    Monitor = 1,
    Enforce = 2,
}

#[repr(C)]
pub struct ShieldConfig {
    pub mode: u32,
    pub block_ttl_65: u32,
    pub block_ttl_129: u32,
}

#[repr(C)]
struct BpfMapElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
struct BpfObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[inline(always)]
unsafe fn sys_bpf(cmd: usize, attr: *const u8, size: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_BPF,
            in("rdi") cmd,
            in("rsi") attr,
            in("rdx") size,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Открывает закреплённую eBPF-карту из `/sys/fs/bpf/...` (путь должен заканчиваться нулевым байтом `\0`)
pub unsafe fn bpf_obj_get(pinned_path_cstr: &[u8]) -> isize {
    let attr = BpfObjAttr {
        pathname: pinned_path_cstr.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    unsafe {
        sys_bpf(
            BPF_OBJ_GET,
            &attr as *const BpfObjAttr as *const u8,
            core::mem::size_of::<BpfObjAttr>(),
        )
    }
}

/// Мгновенно добавляет IPv4-адрес (в big-endian) в динамический белый список XDP за O(1)
pub unsafe fn whitelist_add_ipv4(map_fd: u32, ipv4_be: u32) -> isize {
    let allow: u8 = 1;
    let attr = BpfMapElemAttr {
        map_fd,
        _pad: 0,
        key: &ipv4_be as *const u32 as u64,
        value: &allow as *const u8 as u64,
        flags: 0, // BPF_ANY
    };
    unsafe {
        sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            &attr as *const BpfMapElemAttr as *const u8,
            core::mem::size_of::<BpfMapElemAttr>(),
        )
    }
}

/// Мгновенно удаляет IPv4-адрес из динамического белого списка XDP
pub unsafe fn whitelist_del_ipv4(map_fd: u32, ipv4_be: u32) -> isize {
    let attr = BpfMapElemAttr {
        map_fd,
        _pad: 0,
        key: &ipv4_be as *const u32 as u64,
        value: 0,
        flags: 0,
    };
    unsafe {
        sys_bpf(
            BPF_MAP_DELETE_ELEM,
            &attr as *const BpfMapElemAttr as *const u8,
            core::mem::size_of::<BpfMapElemAttr>(),
        )
    }
}

/// Переключает режим работы XDP-фильтра (Fail-Open / Monitor / Enforce) без перезагрузки программы
pub unsafe fn set_shield_mode(config_map_fd: u32, cfg: &ShieldConfig) -> isize {
    let key: u32 = 0;
    let attr = BpfMapElemAttr {
        map_fd: config_map_fd,
        _pad: 0,
        key: &key as *const u32 as u64,
        value: cfg as *const ShieldConfig as u64,
        flags: 0,
    };
    unsafe {
        sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            &attr as *const BpfMapElemAttr as *const u8,
            core::mem::size_of::<BpfMapElemAttr>(),
        )
    }
}
