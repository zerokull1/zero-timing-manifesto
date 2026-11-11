[zero@zer0 stage0_explorer]$ cat << 'EOF' > src/main.rs
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[repr(C)]
pub struct CpuSignature {
    pub vendor_ebx: u32,
    pub vendor_edx: u32,
    pub vendor_ecx: u32,
}

#[repr(C)]
pub struct PcieDeviceInfo {
    pub vendor_id: u16,
    pub device_id: u16,
}

#[inline(always)]
unsafe fn discover_cpu() -> CpuSignature {
    let mut ebx: u32;
    let mut edx: u32;
    let mut ecx: u32;

    unsafe {
        // Трюк с сохранением RBX:
        // 1. Копируем rbx в rdi, чтобы уберечь его для LLVM
        // 2. Вызываем cpuid (она запишет данные в eax, ebx, ecx, edx)
        // 3. Переносим результат из ebx в переменную ebx_out
        // 4. Восстанавливаем rbx из rdi, возвращая всё на место
        asm!(
            "mov rdi, rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "mov rbx, rdi",
            inout("eax") 0 => _,
            ebx_out = out(reg) ebx,
            out("edx") edx,
            out("ecx") ecx,
            out("rdi") _, // Указываем компилятору, что rdi затирается
            options(nostack, preserves_flags)
        );
    }

    CpuSignature {
        vendor_ebx: ebx,
        vendor_edx: edx,
        vendor_ecx: ecx,
    }
}

unsafe fn pci_config_read_32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address = ((1u32 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)) as u32;

    let mut result: u32;

    unsafe {
        asm!(
            "out dx, eax",
            in("dx") 0xCF8u16,
            in("eax") address,
            options(nostack, preserves_flags)
        );

        asm!(
            "in eax, dx",
            in("dx") 0xCFCu16,
            out("eax") result,
            options(nostack, preserves_flags)
        );
    }

    result
}

unsafe fn discover_gpu() -> PcieDeviceInfo {
    for slot in 0..32 {
        let id_reg = unsafe { pci_config_read_32(0, slot, 0, 0x00) };
        let vendor_id = (id_reg & 0xFFFF) as u16;
        
        if vendor_id != 0xFFFF && vendor_id != 0x0000 {
            let class_reg = unsafe { pci_config_read_32(0, slot, 0, 0x08) };
            let base_class = ((class_reg >> 24) & 0xFF) as u8;

            if base_class == 0x03 {
                let device_id = ((id_reg >> 16) & 0xFFFF) as u16;
                return PcieDeviceInfo { vendor_id, device_id };
            }
        }
    }
    PcieDeviceInfo { vendor_id: 0, device_id: 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let cpu = unsafe { discover_cpu() };
    let gpu = unsafe { discover_gpu() };

    if cpu.vendor_ebx == 0x756e6547 {
        if gpu.vendor_id == 0x10DE {
            // Инициализация BAR для NVIDIA
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
EOF
[zero@zer0 stage0_explorer]$ RUSTFLAGS="-C link-arg=-nostartfiles -C link-arg=-nodefaultlibs" cargo build --release
   Compiling stage0_explorer v0.1.0 (/home/zero/stage0_explorer)
    Finished `release` profile [optimized] target(s) in 0.32s
[zero@zer0 stage0_explorer]$ 
