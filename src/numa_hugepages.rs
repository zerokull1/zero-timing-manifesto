// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;

const SYS_MMAP: u64       = 9;
const SYS_MUNMAP: u64     = 11;
const SYS_MBIND: u64      = 237;

const PROT_READ_WRITE: u64 = 0x3;
const MAP_PRIVATE_ANON: u64 = 0x22;
const MAP_LOCKED: u64      = 0x2000;
const MAP_HUGETLB: u64     = 0x40000;
const MAP_HUGE_2MB: u64    = 21 << 26;
const MPOL_BIND: u64       = 2;

/// Прямой no_std системный вызов mmap (x86_64)
#[inline(always)]
unsafe fn raw_sys_mmap(len: usize, flags: u64) -> isize { unsafe {
    let ret: isize;
    asm!(
        "syscall",
        in("rax") SYS_MMAP,
        in("rdi") 0usize,
        in("rsi") len,
        in("rdx") PROT_READ_WRITE,
        in("r10") flags,
        in("r8") (-1isize) as u64,
        in("r9") 0usize,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret
}}

/// Жёсткая привязка диапазона памяти к конкретному NUMA-узлу (sys_mbind, MPOL_BIND)
#[inline(always)]
pub unsafe fn bind_memory_to_numa_node(ptr: *mut u8, len: usize, numa_node: u32) -> bool { unsafe {
    let nodemask: u64 = 1u64 << (numa_node & 63);
    let ret: isize;
    asm!(
        "syscall",
        in("rax") SYS_MBIND,
        in("rdi") ptr as u64,
        in("rsi") len,
        in("rdx") MPOL_BIND,
        in("r10") (&nodemask as *const u64) as u64,
        in("r8") 64u64,
        in("r9") 0u64,
        out("rcx") _,
        out("r11") _,
        lateout("rax") ret,
        options(nostack)
    );
    ret == 0
}}

/// Выделение стерильной памяти на огромных страницах 2MB (Zero-TLB-Miss) с привязкой к NUMA Node 0
/// Возвращает (указатель, true если выделены реальные 2MB HugePages, false если откат на 4KB LOCKED)
#[inline(always)]
pub unsafe fn alloc_huge_numa_ring(size_bytes: usize, numa_node: u32) -> (*mut u8, bool) { unsafe {
    let aligned_len = (size_bytes + 0x1F_FFFF) & !0x1F_FFFF;

    // 1. Пробуем выделить огромные страницы 2 МБ + заблокировать в физической ОЗУ (MAP_LOCKED)
    let huge_ptr = raw_sys_mmap(aligned_len, MAP_PRIVATE_ANON | MAP_HUGETLB | MAP_HUGE_2MB | MAP_LOCKED);
    if huge_ptr > 0 && (huge_ptr as usize) < 0xFFFF_FFFF_FFFF_0000 {
        let p = huge_ptr as *mut u8;
        let _ = bind_memory_to_numa_node(p, aligned_len, numa_node);
        return (p, true);
    }

    // 2. Безопасный откат на обычные страницы с блокировкой от выгрузки в swap (MAP_LOCKED)
    let std_ptr = raw_sys_mmap(aligned_len, MAP_PRIVATE_ANON | MAP_LOCKED);
    if std_ptr > 0 && (std_ptr as usize) < 0xFFFF_FFFF_FFFF_0000 {
        let p = std_ptr as *mut u8;
        let _ = bind_memory_to_numa_node(p, aligned_len, numa_node);
        return (p, false);
    }

    (core::ptr::null_mut(), false)
}}
