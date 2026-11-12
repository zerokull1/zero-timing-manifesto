#![allow(dead_code)]

use core::arch::asm;

const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
const MSR_IA32_VMX_BASIC: u32       = 0x480;
const CR4_VMXE_BIT: u64             = 1 << 13;

/// Выровненный по 4096 байт регион управления гипервизора (VMXON / VMCB Region)
#[repr(C, align(4096))]
pub struct HypervisorVmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; 4088],
}

impl HypervisorVmcsRegion {
    pub const fn new() -> Self {
        Self {
            revision_id: 0,
            abort_indicator: 0,
            data: [0; 4088],
        }
    }
}

/// Проверка поддержки Intel VT-x (CPUID.01H:ECX[bit 5]) без стандартной библиотеки
#[inline(always)]
pub unsafe fn cpu_supports_vmx() -> bool { unsafe {
    let ecx: u32;
    asm!(
        "push rbx",
        "mov eax, 1",
        "cpuid",
        "pop rbx",
        out("ecx") ecx,
        out("eax") _,
        out("edx") _,
        options(nomem, nostack)
    );
    (ecx & (1 << 5)) != 0
}}

/// Проверка поддержки AMD-V / SVM (CPUID.80000001H:ECX[bit 2])
#[inline(always)]
pub unsafe fn cpu_supports_svm() -> bool { unsafe {
    let ecx: u32;
    asm!(
        "push rbx",
        "mov eax, 0x80000001",
        "cpuid",
        "pop rbx",
        out("ecx") ecx,
        out("eax") _,
        out("edx") _,
        options(nomem, nostack)
    );
    (ecx & (1 << 2)) != 0
}}

/// Подготовка и вход в режим корневого гипервизора (VMX Root Operation, Ring -1)
/// Выполняется в Bare-Metal / UEFI Stage 0 перед запуском Windows или Linux.
#[inline(always)]
pub unsafe fn enter_vmx_root_ring_minus_1(vmxon_region: &mut HypervisorVmcsRegion) -> Result<u32, u32> { unsafe {
    if !cpu_supports_vmx() {
        return Err(1); // Нет аппаратного VT-x
    }

    // 1. Читаем идентификатор ревизии VMCS из MSR 0x480
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") MSR_IA32_VMX_BASIC, out("eax") lo, out("edx") hi, options(nomem, nostack));
    let vmcs_rev_id = lo & 0x7FFF_FFFF;
    let _ = hi;
    vmxon_region.revision_id = vmcs_rev_id;

    // 2. Включаем бит VMXE (bit 13) в управляющем регистре CR4
    let mut cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
    cr4 |= CR4_VMXE_BIT;
    asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));

    // 3. Проверяем и разблокируем VMX вне SMX в IA32_FEATURE_CONTROL (MSR 0x3A)
    let fc_lo: u32;
    let fc_hi: u32;
    asm!("rdmsr", in("ecx") MSR_IA32_FEATURE_CONTROL, out("eax") fc_lo, out("edx") fc_hi, options(nomem, nostack));
    let mut fc = ((fc_hi as u64) << 32) | (fc_lo as u64);
    if (fc & 0x1) == 0 {
        fc |= 0x5; // Lock bit (0) + Enable VMXON outside SMX (bit 2)
        asm!("wrmsr", in("ecx") MSR_IA32_FEATURE_CONTROL, in("eax") fc as u32, in("edx") (fc >> 32) as u32, options(nomem, nostack));
    }

    // 4. Выполняем аппаратную инструкцию VMXON по физическому адресу 4KB-страницы
    let phys_addr = (vmxon_region as *const HypervisorVmcsRegion) as u64;
    let cf_err: u8;
    asm!(
        "vmxon [{addr}]",
        "setc {err}",
        addr = in(reg) &phys_addr,
        err = out(reg_byte) cf_err,
        options(nostack)
    );

    if cf_err != 0 {
        return Err(2); // Ошибка аппаратного входа VMXON
    }

    Ok(vmcs_rev_id)
}}
