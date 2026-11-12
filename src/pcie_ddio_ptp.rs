#![allow(dead_code)]

use core::arch::asm;

// Типовые смещения аппаратных часов PTP (IEEE 1588 PHC) в BAR0 сетевых контроллеров Intel (i210/i225/X710)
const NIC_REG_SYSTIML: usize = 0x0B600; // Наносекундная часть аппаратных часов на плате NIC
const NIC_REG_SYSTIMH: usize = 0x0B604; // Секундная часть аппаратных часов на плате NIC

/// Подготовка 64-байтной кэш-линии RX-дескриптора в L3-кэше для прямой инжекции Intel DDIO
/// (Сетевая карта кладёт пакет по PCIe DMA сразу в L3-кэш процессора, минуя DDR)
#[inline(always)]
pub unsafe fn ddio_prime_rx_cacheline(rx_desc_ptr: *mut u8) {
    asm!(
        "prefetchw [{p}]",
        p = in(reg) rx_desc_ptr,
        options(nostack)
    );
}

/// Чтение наносекундного аппаратного времени напрямую из кварцевого генератора сетевой карты (PTP IEEE 1588 PHC)
/// Выполняет двойное чтение SYSTIMH -> SYSTIML -> SYSTIMH для защиты от переполнения секунды на границе тика.
#[inline(always)]
pub unsafe fn read_nic_ptp_hw_ns(bar0_base: *const u8) -> u64 {
    if bar0_base.is_null() {
        return 0;
    }
    let reg_l = bar0_base.add(NIC_REG_SYSTIML) as *const u32;
    let reg_h = bar0_base.add(NIC_REG_SYSTIMH) as *const u32;

    let sec1 = core::ptr::read_volatile(reg_h);
    let nsec = core::ptr::read_volatile(reg_l);
    let sec2 = core::ptr::read_volatile(reg_h);

    let sec = if sec1 == sec2 { sec1 } else { sec2 };
    (sec as u64) * 1_000_000_000u64 + (nsec as u64)
}
