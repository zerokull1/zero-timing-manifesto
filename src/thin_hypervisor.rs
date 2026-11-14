#![allow(dead_code)]

use core::arch::asm;

// Архитектурные MSR: Intel VT-x / EPT и AMD-V / SVM (Pure x86_64)
const MSR_IA32_FEATURE_CONTROL: u32  = 0x3A;
const MSR_IA32_VMX_BASIC: u32        = 0x480;
const MSR_IA32_VMX_CR0_FIXED0: u32   = 0x486;
const MSR_IA32_VMX_CR0_FIXED1: u32   = 0x487;
const MSR_IA32_VMX_CR4_FIXED0: u32   = 0x488;
const MSR_IA32_VMX_CR4_FIXED1: u32   = 0x489;
const MSR_IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;

const MSR_AMD_VM_CR: u32             = 0xC001_0114;
const MSR_AMD_VM_HSAVE_PA: u32       = 0xC001_0117;
const MSR_IA32_EFER: u32             = 0xC000_0080;
const EFER_SVME_BIT: u64             = 1 << 12;
const CR4_VMXE_BIT: u64              = 1 << 13;

// Порты IPMI KCS для Out-of-Band алерта в BMC стойки
const IPMI_KCS_DATA_PORT: u16        = 0x0CA2;
const IPMI_KCS_CMD_PORT: u16         = 0x0CA3;

pub const MAX_RACK_CORES: usize      = 128;

// Поля VMCS (Intel SDM Vol. 3D)
pub const VMCS_CTRL_EPT_POINTER: u64      = 0x0000_201A;
pub const VMCS_RO_EXIT_REASON: u64        = 0x0000_4402;
pub const VMCS_RO_EXIT_QUALIFICATION: u64 = 0x0000_6400;

// Права доступа EPT / NPT
pub const EPT_READ: u64        = 1 << 0;
pub const EPT_WRITE: u64       = 1 << 1;
pub const EPT_EXECUTE: u64     = 1 << 2;
pub const EPT_MEM_TYPE_WB: u64 = 6 << 3;
pub const EPT_PERM_RO: u64     = EPT_READ | EPT_MEM_TYPE_WB;
pub const EPT_PERM_XO: u64     = EPT_EXECUTE | EPT_MEM_TYPE_WB; // Execute-Only (R=0, W=0, X=1)

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HypervisorBackend {
    NoneOrRestricted = 0,
    IntelVtxEpt      = 1,
    AmdSvmNpt        = 2,
}

#[repr(C, align(4096))]
pub struct HypervisorControlRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; 4088],
}

impl HypervisorControlRegion {
    pub const fn new() -> Self {
        Self { revision_id: 0, abort_indicator: 0, data: [0; 4088] }
    }
}

#[repr(C, align(4096))]
pub struct PerCoreRackContext {
    pub vmxon_or_hsave: HypervisorControlRegion,
    pub vmcs_or_vmcb: HypervisorControlRegion,
    pub apic_id: u32,
    pub backend: HypervisorBackend,
    pub armed: u8,
    pub _pad: [u8; 3],
}

impl PerCoreRackContext {
    pub const fn new() -> Self {
        Self {
            vmxon_or_hsave: HypervisorControlRegion::new(),
            vmcs_or_vmcb: HypervisorControlRegion::new(),
            apic_id: 0,
            backend: HypervisorBackend::NoneOrRestricted,
            armed: 0,
            _pad: [0; 3],
        }
    }
}

#[repr(C, align(4096))]
pub struct EptPageTable {
    pub entries: [u64; 512],
}

impl EptPageTable {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }

    #[inline(always)]
    pub fn map_execute_only_4k(&mut self, index: usize, host_phys_addr: u64) {
        if index < 512 {
            self.entries[index] = (host_phys_addr & 0x000F_FFFF_FFFF_F000) | EPT_PERM_XO;
        }
    }

    #[inline(always)]
    pub fn map_read_only_4k(&mut self, index: usize, host_phys_addr: u64) {
        if index < 512 {
            self.entries[index] = (host_phys_addr & 0x000F_FFFF_FFFF_F000) | EPT_PERM_RO;
        }
    }

    #[inline(always)]
    pub fn as_eptp(&self) -> u64 {
        let pml4_phys = (self as *const Self) as u64;
        (pml4_phys & 0x000F_FFFF_FFFF_F000) | (3 << 3) | 6
    }
}

#[inline(always)]
unsafe fn rdmsr(msr: u32) -> u64 { unsafe {
    let lo: u32;
    let hi: u32;
    asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}}

#[inline(always)]
unsafe fn wrmsr(msr: u32, val: u64) { unsafe {
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") val as u32,
        in("edx") (val >> 32) as u32,
        options(nomem, nostack)
    );
}}

#[inline(always)]
pub unsafe fn current_x2apic_id() -> u32 { unsafe {
    let edx: u32;
    asm!(
        "push rbx",
        "mov eax, 0x0B",
        "xor ecx, ecx",
        "cpuid",
        "pop rbx",
        out("edx") edx,
        out("eax") _,
        out("ecx") _,
        options(nomem, nostack)
    );
    edx
}}

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

#[inline(always)]
pub unsafe fn cpu_supports_ept_execute_only() -> bool { unsafe {
    if !cpu_supports_vmx() { return false; }
    (rdmsr(MSR_IA32_VMX_EPT_VPID_CAP) & 1) != 0
}}

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

#[inline(always)]
pub unsafe fn detect_rack_cpu_backend() -> HypervisorBackend { unsafe {
    if cpu_supports_vmx() {
        HypervisorBackend::IntelVtxEpt
    } else if cpu_supports_svm() {
        HypervisorBackend::AmdSvmNpt
    } else {
        HypervisorBackend::NoneOrRestricted
    }
}}

#[inline(always)]
pub unsafe fn arm_rack_core_ring_minus_1(ctx: &mut PerCoreRackContext) -> Result<HypervisorBackend, u32> { unsafe {
    ctx.apic_id = current_x2apic_id();

    match detect_rack_cpu_backend() {
        HypervisorBackend::IntelVtxEpt => {
            let rev_id = (rdmsr(MSR_IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF;
            ctx.vmxon_or_hsave.revision_id = rev_id;

            let mut cr0: u64;
            asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
            cr0 = (cr0 & rdmsr(MSR_IA32_VMX_CR0_FIXED1)) | rdmsr(MSR_IA32_VMX_CR0_FIXED0);
            asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));

            let mut cr4: u64;
            asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
            cr4 = ((cr4 | CR4_VMXE_BIT) & rdmsr(MSR_IA32_VMX_CR4_FIXED1)) | rdmsr(MSR_IA32_VMX_CR4_FIXED0);
            asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));

            let mut fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
            if (fc & 0x1) == 0 {
                fc |= 0x5;
                wrmsr(MSR_IA32_FEATURE_CONTROL, fc);
            } else if (fc & (1 << 2)) == 0 {
                return Err(3);
            }

            let phys_addr = (&ctx.vmxon_or_hsave as *const HypervisorControlRegion) as u64;
            let cf_err: u8;
            asm!("vmxon [{addr}]", "setc {err}", addr = in(reg) &phys_addr, err = out(reg_byte) cf_err, options(nostack));
            if cf_err != 0 { return Err(2); }

            ctx.backend = HypervisorBackend::IntelVtxEpt;
            ctx.armed = 1;
            Ok(HypervisorBackend::IntelVtxEpt)
        }
        HypervisorBackend::AmdSvmNpt => {
            if (rdmsr(MSR_AMD_VM_CR) & (1 << 4)) != 0 { return Err(3); }
            let efer = rdmsr(MSR_IA32_EFER) | EFER_SVME_BIT;
            wrmsr(MSR_IA32_EFER, efer);

            let hsave_phys = (&ctx.vmxon_or_hsave as *const HypervisorControlRegion) as u64;
            wrmsr(MSR_AMD_VM_HSAVE_PA, hsave_phys & 0x000F_FFFF_FFFF_F000);

            ctx.backend = HypervisorBackend::AmdSvmNpt;
            ctx.armed = 1;
            Ok(HypervisorBackend::AmdSvmNpt)
        }
        HypervisorBackend::NoneOrRestricted => Err(1),
    }
}}

/// Обратная совместимость с Stage 0 UEFI вызовом
#[inline(always)]
pub unsafe fn enter_vmx_root_ring_minus_1(vmxon_region: &mut HypervisorControlRegion) -> Result<u32, u32> { unsafe {
    if !cpu_supports_vmx() { return Err(1); }
    let rev_id = (rdmsr(MSR_IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF;
    vmxon_region.revision_id = rev_id;

    let mut cr0: u64;
    asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
    cr0 = (cr0 & rdmsr(MSR_IA32_VMX_CR0_FIXED1)) | rdmsr(MSR_IA32_VMX_CR0_FIXED0);
    asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack));

    let mut cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
    cr4 = ((cr4 | CR4_VMXE_BIT) & rdmsr(MSR_IA32_VMX_CR4_FIXED1)) | rdmsr(MSR_IA32_VMX_CR4_FIXED0);
    asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack));

    let mut fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
    if (fc & 0x1) == 0 {
        fc |= 0x5;
        wrmsr(MSR_IA32_FEATURE_CONTROL, fc);
    } else if (fc & (1 << 2)) == 0 {
        return Err(3);
    }

    let phys_addr = (vmxon_region as *const HypervisorControlRegion) as u64;
    let cf_err: u8;
    asm!("vmxon [{addr}]", "setc {err}", addr = in(reg) &phys_addr, err = out(reg_byte) cf_err, options(nostack));
    if cf_err != 0 { return Err(2); }
    Ok(rev_id)
}}

/// Сброс и активация рабочего VMCS на Intel (VMCLEAR + VMPTRLD)
#[inline(always)]
pub unsafe fn activate_intel_vmcs(ctx: &mut PerCoreRackContext) -> Result<(), u32> { unsafe {
    ctx.vmcs_or_vmcb.revision_id = (rdmsr(MSR_IA32_VMX_BASIC) as u32) & 0x7FFF_FFFF;
    let phys_addr = (&ctx.vmcs_or_vmcb as *const HypervisorControlRegion) as u64;
    let err_flags: u8;
    asm!(
        "vmclear [{addr}]",
        "setbe {err}",
        "test {err}, {err}",
        "jnz 2f",
        "vmptrld [{addr}]",
        "setbe {err}",
        "2:",
        addr = in(reg) &phys_addr,
        err = out(reg_byte) err_flags,
        options(nostack)
    );
    if err_flags != 0 { return Err(4); }
    Ok(())
}}

/// Аппаратная запись поля VMCS (VMWRITE)
#[inline(always)]
pub unsafe fn vmwrite(field: u64, value: u64) -> bool { unsafe {
    let err: u8;
    asm!("vmwrite {val}, {fld}", "setbe {err}", fld = in(reg) field, val = in(reg) value, err = out(reg_byte) err, options(nomem, nostack));
    err == 0
}}

/// Аппаратное чтение поля VMCS (VMREAD)
#[inline(always)]
pub unsafe fn vmread(field: u64) -> u64 { unsafe {
    let val: u64;
    asm!("vmread {val}, {fld}", fld = in(reg) field, val = out(reg) val, options(nomem, nostack));
    val
}}

/// Аппаратный Out-of-Band сброс тревоги напрямую в BMC стойки через порт IPMI KCS (0xCA2/0xCA3)
#[inline(always)]
pub unsafe fn trigger_bmc_ipmi_alert(violation_code: u8) { unsafe {
    asm!(
        "mov dx, {cmd_port}",
        "mov al, 0x61",
        "out dx, al",
        "mov dx, {data_port}",
        "mov al, {code}",
        "out dx, al",
        cmd_port = const IPMI_KCS_CMD_PORT,
        data_port = const IPMI_KCS_DATA_PORT,
        code = in(reg_byte) violation_code,
        options(nomem, nostack)
    );
}}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmExitVerdict {
    AdvanceGuestRip       = 0,
    SecurityViolationTrap = 1,
}

/// Безветвящаяся классификация причины перехвата (единая для Intel VM-Exit и AMD #VMEXIT)
#[inline(always)]
pub fn classify_vmexit_branchless(backend: HypervisorBackend, exit_reason: u32) -> VmExitVerdict {
    let basic_reason = exit_reason & 0xFFFF;
    let verdict: u32;
    unsafe {
        match backend {
            HypervisorBackend::IntelVtxEpt => {
                asm!(
                    "xor {res:e}, {res:e}",
                    "mov {tmp:e}, 1",
                    "cmp {rsn:e}, 48",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 49",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 28",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 32",
                    "cmove {res:e}, {tmp:e}",
                    rsn = in(reg) basic_reason,
                    res = out(reg) verdict,
                    tmp = out(reg) _,
                    options(pure, nomem, nostack)
                );
            }
            HypervisorBackend::AmdSvmNpt => {
                asm!(
                    "xor {res:e}, {res:e}",
                    "mov {tmp:e}, 1",
                    "cmp {rsn:e}, 0x400",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 0x07C",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 0x010",
                    "cmove {res:e}, {tmp:e}",
                    "cmp {rsn:e}, 0x014",
                    "cmove {res:e}, {tmp:e}",
                    rsn = in(reg) basic_reason,
                    res = out(reg) verdict,
                    tmp = out(reg) _,
                    options(pure, nomem, nostack)
                );
            }
            HypervisorBackend::NoneOrRestricted => {
                verdict = 0;
            }
        }
    }
    if verdict == 1 { VmExitVerdict::SecurityViolationTrap } else { VmExitVerdict::AdvanceGuestRip }
}
