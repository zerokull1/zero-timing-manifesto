#![no_std]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

static TARGET_SEC_ID: AtomicU32 = AtomicU32::new(0);
static LAST_SEQ_NUM: AtomicU32 = AtomicU32::new(0);

#[repr(C, align(64))]
pub struct ZeroMarketTick {
    pub exchange_ts_ns: u64,
    pub security_id: u32,
    pub msg_seq_num: u32,
    pub best_bid_price: i64,
    pub best_bid_qty: u64,
    pub best_ask_price: i64,
    pub best_ask_qty: u64,
    pub local_tsc_cycles: u64,
}

#[inline(always)]
unsafe fn rdtsc_start() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn rdtscp_end() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[no_mangle]
pub extern "C" fn zero_hft_init(target_security_id: u32) {
    TARGET_SEC_ID.store(target_security_id, Ordering::Release);
    LAST_SEQ_NUM.store(0, Ordering::Release);
}

/// Zero-Copy разбор биржевого UDP-пакета (14 Eth + 20 IPv4 + 8 UDP = 42 байта заголовков + 48 байт SBE payload)
#[no_mangle]
pub unsafe extern "C" fn zero_hft_on_market_frame(
    frame_ptr: *const u8,
    frame_len: usize,
    max_buy_price: i64,
    min_sell_price: i64,
    out_tick: *mut ZeroMarketTick,
) -> u32 {
    if frame_ptr.is_null() || out_tick.is_null() || frame_len < 90 {
        return 0;
    }

    let t0 = rdtsc_start();

    // Проверка IPv4 (0x0800) и UDP (proto == 17)
    let eth_proto = u16::from_be(core::ptr::read_unaligned(frame_ptr.add(12) as *const u16));
    let ip_proto = *frame_ptr.add(23);
    if eth_proto != 0x0800 || ip_proto != 17 {
        return 0;
    }

    // Прямое чтение бинарного SBE-сообщения со смещения 42 (без парсинга и без копирования)
    let sbe = frame_ptr.add(42);
    let sec_id = core::ptr::read_unaligned(sbe as *const u32);
    if sec_id != TARGET_SEC_ID.load(Ordering::Acquire) {
        return 0;
    }

    let seq_num = core::ptr::read_unaligned(sbe.add(4) as *const u32);
    let prev_seq = LAST_SEQ_NUM.swap(seq_num, Ordering::AcqRel);

    // Защита от спуфинга / дубликатов последовательности (Sequence Replay Guard)
    if prev_seq != 0 && seq_num <= prev_seq {
        return 3; // HFT_ACTION_DROP_SPOOF
    }

    let exch_ts = core::ptr::read_unaligned(sbe.add(8) as *const u64);
    let bid_px  = core::ptr::read_unaligned(sbe.add(16) as *const i64);
    let bid_qty = core::ptr::read_unaligned(sbe.add(24) as *const u64);
    let ask_px  = core::ptr::read_unaligned(sbe.add(32) as *const i64);
    let ask_qty = core::ptr::read_unaligned(sbe.add(40) as *const u64);

    // Безветвящееся принятие торгового решения (x86_64 cmov):
    // Если ask_px <= max_buy_price и ask_qty > 0 -> BUY (1)
    // Если bid_px >= min_sell_price и bid_qty > 0 -> SELL (2)
    let mut action: u64 = 0;
    asm!(
        "cmp {ask}, {max_b}",
        "jg 2f",
        "test {aqty}, {aqty}",
        "jz 2f",
        "mov {act}, 1",
        "2:",
        "cmp {bid}, {min_s}",
        "jl 3f",
        "test {bqty}, {bqty}",
        "jz 3f",
        "mov {act}, 2",
        "3:",
        ask = in(reg) ask_px,
        max_b = in(reg) max_buy_price,
        aqty = in(reg) ask_qty,
        bid = in(reg) bid_px,
        min_s = in(reg) min_sell_price,
        bqty = in(reg) bid_qty,
        act = inout(reg) action,
        options(pure, nomem, nostack)
    );

    let t1 = rdtscp_end();

    (*out_tick).exchange_ts_ns = exch_ts;
    (*out_tick).security_id = sec_id;
    (*out_tick).msg_seq_num = seq_num;
    (*out_tick).best_bid_price = bid_px;
    (*out_tick).best_bid_qty = bid_qty;
    (*out_tick).best_ask_price = ask_px;
    (*out_tick).best_ask_qty = ask_qty;
    (*out_tick).local_tsc_cycles = t1.saturating_sub(t0);

    action as u32
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
