#![allow(dead_code)]

use core::arch::asm;

/// Состояние автономного адаптивного шлюза (выровнено по кэш-линии 64 байта)
#[repr(C, align(64))]
pub struct AdaptiveDdosGateway {
    /// Текущий порог энтропии Шеннона в формате Q16.16 (по умолчанию 3.50 бита = 229376)
    pub entropy_threshold_q16: u32,
    /// Базовый порог для быстрого возврата после спада атаки
    pub base_threshold_q16: u32,
    /// Счётчик адаптированных (заблокированных) аномальных потоков
    pub mitigated_flows: u64,
    /// Режим жёсткой блокировки (0 = штатный, 1 = карантин)
    pub lockdown_level: u32,
    pub _pad: [u32; 9],
}

impl AdaptiveDdosGateway {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            entropy_threshold_q16: 229_376, // 3.50 bits (Q16.16)
            base_threshold_q16: 229_376,
            mitigated_flows: 0,
            lockdown_level: 0,
            _pad: [0; 9],
        }
    }

    /// Безветвящийся ассемблерный вердикт шлюза (cmova) на основе спектральной энтропии потока:
    /// Возвращает: 0 = PASS, 1 = QUARANTINE (подозрительный всплеск), 2 = HARD DROP (атака)
    #[inline(always)]
    pub unsafe fn evaluate_flow_asm(&mut self, flow_entropy_q16: u32, packet_score: u32) -> u32 { unsafe {
        let mut verdict: u32 = 0;
        let thresh = self.entropy_threshold_q16;
        let hard_thresh = thresh.wrapping_add(32_768); // +0.50 бита сверх порога -> мгновенный DROP

        #[cfg(target_arch = "x86_64")]
        asm!(
            "mov {v:e}, 0",
            "mov {q:e}, 1",
            "mov {d:e}, 2",
            "cmp {ent:e}, {t1:e}",
            "cmova {v:e}, {q:e}",
            "cmp {ent:e}, {t2:e}",
            "cmova {v:e}, {d:e}",
            ent = in(reg) flow_entropy_q16,
            t1 = in(reg) thresh,
            t2 = in(reg) hard_thresh,
            v = out(reg) verdict,
            q = out(reg) _,
            d = out(reg) _,
            options(pure, nomem, nostack)
        );

        #[cfg(not(target_arch = "x86_64"))]
        {
            if flow_entropy_q16 > hard_thresh {
                verdict = 2;
            } else if flow_entropy_q16 > thresh {
                verdict = 1;
            }
        }

        // Адаптивная подстройка порога без ветвлений: при атаке порог затягивается ниже, в покое плавно отпускает
        let is_attack = (verdict != 0) as u32;
        self.mitigated_flows = self.mitigated_flows.wrapping_add(is_attack as u64);
        self.lockdown_level = is_attack;

        let tightened = self.entropy_threshold_q16.saturating_sub(512);
        let relaxed = self.entropy_threshold_q16.saturating_add(128).min(self.base_threshold_q16);
        self.entropy_threshold_q16 = if is_attack != 0 {
            tightened.max(163_840) // Не ниже 2.50 бита
        } else {
            relaxed
        };

        let _ = packet_score;
        verdict
    }}
}
