use crate::mem_guard::wipe_secret;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut pad = [0u8; 128];
    let len = if data.len() < 56 { 64 } else { 128 };
    pad[..data.len()].copy_from_slice(data); pad[data.len()] = 0x80;
    pad[len - 8..len].copy_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for ch in pad[..len].chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 { w[i] = u32::from_be_bytes([ch[i*4], ch[i*4+1], ch[i*4+2], ch[i*4+3]]); }
        for i in 16..80 { w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1); }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d; d = c; c = b.rotate_left(30); b = a; a = t;
        }
        h = h.wrapping_add(a); h = h.wrapping_add(b); h = h.wrapping_add(c); h = h.wrapping_add(d); h = h.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

pub unsafe fn generate_totp(secret: &[u8], secs: u64) -> u32 {
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5Cu8; 64]);
    for i in 0..secret.len().min(64) { ipad[i] ^= secret[i]; opad[i] ^= secret[i]; }
    let mut ibuf = [0u8; 72]; ibuf[..64].copy_from_slice(&ipad); ibuf[64..72].copy_from_slice(&(secs / 30).to_be_bytes());
    let ihash = sha1(&ibuf);
    let mut obuf = [0u8; 84]; obuf[..64].copy_from_slice(&opad); obuf[64..84].copy_from_slice(&ihash);
    let dig = sha1(&obuf);
    wipe_secret(&mut ipad); wipe_secret(&mut opad); wipe_secret(&mut ibuf); wipe_secret(&mut obuf);
    let off = (dig & 0x0F) as usize;
    (((dig[off] as u32 & 0x7F) << 24) | ((dig[off+1] as u32) << 16) | ((dig[off+2] as u32) << 8) | (dig[off+3] as u32)) % 1_000_000
}
