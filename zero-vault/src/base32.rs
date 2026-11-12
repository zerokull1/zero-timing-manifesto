pub fn decode_base32(input: &[u8], out: &mut [u8]) -> usize {
    let (mut buf, mut bits, mut n) = (0u32, 0u8, 0usize);
    for &b in input {
        let v = match b { b'A'..=b'Z' => b - b'A', b'a'..=b'z' => b - b'a', b'2'..=b'7' => b - b'2' + 26, _ => continue };
        buf = (buf << 5) | (v as u32); bits += 5;
        if bits >= 8 { bits -= 8; if n < out.len() { out[n] = ((buf >> bits) & 0xFF) as u8; n += 1; } }
    }
    n
}
