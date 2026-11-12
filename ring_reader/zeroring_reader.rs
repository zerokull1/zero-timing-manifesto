use std::env;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};

const ZERO_RING_MAGIC: u64 = 0x5A45_524F_5249_4E47;

#[repr(C, align(64))]
struct ZeroRingHeader {
    magic: u64,
    version: u32,
    cpu_cores_active: u32,
    write_idx: AtomicU64,
    read_idx: AtomicU64,
    blocked_l3_l4_count: AtomicU64,
    blocked_l7_count: AtomicU64,
    last_entropy_q16: u64,
}

#[cfg(unix)]
unsafe fn map_ring(path: &str, phys_offset: u64) -> Result<*const ZeroRingHeader, String> {
    use std::os::unix::io::AsRawFd;
    extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    }
    let file = OpenOptions::new().read(true).open(path).map_err(|e| e.to_string())?;
    let ptr = mmap(std::ptr::null_mut(), 4096, 1, 1, file.as_raw_fd(), phys_offset as i64);
    if ptr as isize == -1 {
        return Err("mmap failed (check permissions or /dev/shm)".into());
    }
    Ok(ptr as *const ZeroRingHeader)
}

#[cfg(windows)]
unsafe fn map_ring(name: &str, _phys_offset: u64) -> Result<*const ZeroRingHeader, String> {
    extern "system" {
        fn OpenFileMappingA(access: u32, inherit: i32, name: *const u8) -> isize;
        fn MapViewOfFile(handle: isize, access: u32, off_hi: u32, off_lo: u32, bytes: usize) -> *const u8;
    }
    let mut cname = name.as_bytes().to_vec();
    cname.push(0);
    let h = OpenFileMappingA(0x0004, 0, cname.as_ptr());
    if h == 0 {
        return Err("OpenFileMappingA failed (ZERORING object not found)".into());
    }
    let ptr = MapViewOfFile(h, 0x0004, 0, 0, 4096);
    if ptr.is_null() {
        return Err("MapViewOfFile failed".into());
    }
    Ok(ptr as *const ZeroRingHeader)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    #[cfg(unix)]
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/shm/zero_shield_ring");
    #[cfg(windows)]
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("Global\\ZeroShieldRing");
    let offset = args.get(2).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0);

    unsafe {
        match map_ring(target, offset) {
            Ok(hdr) => {
                let magic = std::ptr::read_volatile(&(*hdr).magic);
                if magic != ZERO_RING_MAGIC {
                    println!("[ZERORING] Target mapped ({}), magic=0x{:016X} (awaiting Stage 0 / Active Shield init)", target, magic);
                    return;
                }
                let ver = std::ptr::read_volatile(&(*hdr).version);
                let cores = std::ptr::read_volatile(&(*hdr).cpu_cores_active);
                let w = (*hdr).write_idx.load(Ordering::Acquire);
                let l3 = (*hdr).blocked_l3_l4_count.load(Ordering::Acquire);
                let l7 = (*hdr).blocked_l7_count.load(Ordering::Acquire);
                let ent = std::ptr::read_volatile(&(*hdr).last_entropy_q16) as f64 / 65536.0;
                println!("[ZERORING ONLINE] v{} | Cores: {} | Slots Written: {} | L3/L4 Blocked: {} | L7 Blocked: {} | Entropy H: {:.4} bits",
                    ver, cores, w, l3, l7, ent);
            }
            Err(e) => println!("[ZERORING ERROR] {}", e),
        }
    }
}
