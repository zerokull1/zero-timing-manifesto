#![allow(dead_code)]

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NicBackendMode {
    DrvZeroCopy = 1,
    DrvCopy     = 2,
    SkbGeneric  = 3,
    CAbiBridge  = 4, // DPDK / netmap / PF_RING / Snort DAQ
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

/// Единый zero-allocation трейт для подключения любых сетевых движков
/// (AF_XDP, DPDK, netmap, PF_RING, Snort/Suricata DAQ)
pub trait NicDriver {
    fn init_with_cascade(&mut self, ifindex: u32) -> Result<NicBackendMode, i32>;
    fn rx_burst<'a>(&mut self, batch: &mut [&'a [u8]]) -> usize;
    fn tx_burst(&mut self, packets: &[&[u8]]) -> usize;
    fn active_mode(&self) -> NicBackendMode;
}

/// Автоматический каскад инициализации сокета:
/// 1) XDP_ZEROCOPY -> 2) XDP_COPY -> 3) XDP_FLAGS_SKB_MODE
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
