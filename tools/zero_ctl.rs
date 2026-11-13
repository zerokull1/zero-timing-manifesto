#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const SYS_WRITE: usize = 1;
const SYS_EXIT: usize = 60;
const SYS_BPF: usize = 321;

const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_MAP_DELETE_ELEM: usize = 3;
const BPF_OBJ_GET: usize = 7;

const PATH_WHITELIST: &[u8] = b"/sys/fs/bpf/zero_shield/whitelist_v4\0";
const PATH_CONFIG: &[u8] = b"/sys/fs/bpf/zero_shield/config_map\0";

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

#[repr(C)]
struct ShieldConfig {
    mode: u32,
    block_ttl_65: u32,
    block_ttl_129: u32,
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const i8) -> usize {
    let mut len = 0;
    unsafe {
        while core::ptr::read_volatile((s as *const u8).add(len)) != 0 {
            len += 1;
        }
    }
    len
}

#[inline(always)]
unsafe fn sys_write(fd: usize, buf: &[u8]) {
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") fd,
            in("rsi") buf.as_ptr(),
            in("rdx") buf.len(),
            lateout("rax") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
}

#[inline(always)]
unsafe fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") code,
            options(noreturn)
        );
    }
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

unsafe fn bpf_obj_get(path: &[u8]) -> isize {
    let attr = BpfObjAttr {
        pathname: path.as_ptr() as u64,
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

unsafe fn cstr_to_slice<'a>(ptr: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(ptr, strlen(ptr as *const i8)) }
}

fn parse_ipv4_be(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut idx = 0;
    let mut acc: u16 = 0;
    let mut has_digit = false;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            acc = acc * 10 + (b - b'0') as u16;
            if acc > 255 {
                return None;
            }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || idx >= 3 {
                return None;
            }
            octets[idx] = acc as u8;
            idx += 1;
            acc = 0;
            has_digit = false;
        } else {
            return None;
        }
    }
    if !has_digit || idx != 3 {
        return None;
    }
    octets[3] = acc as u8;
    Some(u32::from_ne_bytes(octets))
}

fn print_usage() {
    unsafe {
        sys_write(
            1,
            b"Usage:\n  zero-ctl allow <IPv4>\n  zero-ctl deny <IPv4>\n  zero-ctl mode <fail-open|monitor|enforce>\n",
        );
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mov rdi, rsp", "jmp {entry}", entry = sym rust_main);
}

unsafe extern "C" fn rust_main(stack_ptr: *const usize) -> ! {
    unsafe {
        let argc = *stack_ptr;
        let argv = stack_ptr.add(1) as *const *const u8;

        if argc < 3 {
            print_usage();
            sys_exit(1);
        }

        let cmd = cstr_to_slice(*argv.add(1));
        let arg = cstr_to_slice(*argv.add(2));

        if cmd == b"allow" || cmd == b"deny" {
            let ip_be = match parse_ipv4_be(arg) {
                Some(v) => v,
                None => {
                    sys_write(2, b"[ERR] Invalid IPv4 address\n");
                    sys_exit(1);
                }
            };

            let fd = bpf_obj_get(PATH_WHITELIST);
            if fd < 0 {
                sys_write(2, b"[ERR] Cannot open /sys/fs/bpf/zero_shield/whitelist_v4\n");
                sys_exit(1);
            }

            let allow: u8 = 1;
            let attr = BpfMapElemAttr {
                map_fd: fd as u32,
                _pad: 0,
                key: &ip_be as *const u32 as u64,
                value: if cmd == b"allow" { &allow as *const u8 as u64 } else { 0 },
                flags: 0,
            };

            let syscall_cmd = if cmd == b"allow" { BPF_MAP_UPDATE_ELEM } else { BPF_MAP_DELETE_ELEM };
            let res = sys_bpf(
                syscall_cmd,
                &attr as *const BpfMapElemAttr as *const u8,
                core::mem::size_of::<BpfMapElemAttr>(),
            );

            if res == 0 {
                sys_write(1, b"[OK] Whitelist updated\n");
                sys_exit(0);
            } else {
                sys_write(2, b"[ERR] BPF map operation failed\n");
                sys_exit(1);
            }
        } else if cmd == b"mode" {
            let mode_val = if arg == b"fail-open" {
                0
            } else if arg == b"monitor" {
                1
            } else if arg == b"enforce" {
                2
            } else {
                print_usage();
                sys_exit(1);
            };

            let fd = bpf_obj_get(PATH_CONFIG);
            if fd < 0 {
                sys_write(2, b"[ERR] Cannot open /sys/fs/bpf/zero_shield/config_map\n");
                sys_exit(1);
            }

            let key: u32 = 0;
            let cfg = ShieldConfig {
                mode: mode_val,
                block_ttl_65: 1,
                block_ttl_129: 1,
            };
            let attr = BpfMapElemAttr {
                map_fd: fd as u32,
                _pad: 0,
                key: &key as *const u32 as u64,
                value: &cfg as *const ShieldConfig as u64,
                flags: 0,
            };

            let res = sys_bpf(
                BPF_MAP_UPDATE_ELEM,
                &attr as *const BpfMapElemAttr as *const u8,
                core::mem::size_of::<BpfMapElemAttr>(),
            );

            if res == 0 {
                sys_write(1, b"[OK] Shield mode updated\n");
                sys_exit(0);
            } else {
                sys_write(2, b"[ERR] Failed to update config_map\n");
                sys_exit(1);
            }
        } else {
            print_usage();
            sys_exit(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { sys_exit(1) }
}
