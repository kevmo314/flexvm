//! CRC32C, the checksum of checkpoint pages. With SSE4.2 a page is three interleaved streams
//! (`crc32` has 3-cycle latency but issues every cycle) combined with shift tables; the same
//! pass tells whether the page is all zero.

use std::sync::OnceLock;

const POLY: u32 = 0x82F6_3B78;

fn table() -> &'static [u32; 256] {
    static T: OnceLock<[u32; 256]> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *e = c;
        }
        t
    })
}

/// No pre- or post-inversion.
fn update_sw(mut c: u32, bytes: &[u8]) -> u32 {
    let t = table();
    for &b in bytes {
        c = t[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

#[cfg(target_arch = "x86_64")]
fn has_sse42() -> bool {
    std::arch::is_x86_feature_detected!("sse4.2")
}

#[cfg(not(target_arch = "x86_64"))]
fn has_sse42() -> bool {
    false
}

fn update(c: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    if has_sse42() {
        // SAFETY: the CPU has SSE4.2.
        return unsafe { hw::update(c, bytes) };
    }
    update_sw(c, bytes)
}

pub fn crc32c(bytes: &[u8]) -> u32 {
    !update(!0, bytes)
}

#[cfg(target_arch = "x86_64")]
const STREAM: usize = crate::util::PAGE_SIZE / 24 * 8;

/// Advance a CRC register over `STREAM` zero bytes, a register byte at a time (it is linear).
#[cfg(target_arch = "x86_64")]
fn shift_tables() -> &'static [[u32; 256]; 4] {
    static T: OnceLock<[[u32; 256]; 4]> = OnceLock::new();
    T.get_or_init(|| {
        let zeros = [0u8; STREAM];
        let bit: Vec<u32> = (0..32).map(|i| update_sw(1 << i, &zeros)).collect();
        let mut t = [[0u32; 256]; 4];
        for (k, tk) in t.iter_mut().enumerate() {
            for (b, e) in tk.iter_mut().enumerate() {
                *e = (0..8).filter(|i| b & (1 << i) != 0).fold(0, |a, i| a ^ bit[8 * k + i]);
            }
        }
        t
    })
}

pub fn page(p: &[u8]) -> (u32, bool) {
    debug_assert_eq!(p.len(), crate::util::PAGE_SIZE);
    #[cfg(target_arch = "x86_64")]
    if has_sse42() {
        // SAFETY: the CPU has SSE4.2.
        return unsafe { hw::page(p, shift_tables()) };
    }
    let zero = p.chunks_exact(8).fold(0u64, |a, w| a | u64::from_ne_bytes(w.try_into().unwrap())) == 0;
    (crc32c(p), zero)
}

#[cfg(target_arch = "x86_64")]
mod hw {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};

    use super::STREAM;

    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn update(c: u32, bytes: &[u8]) -> u32 {
        let mut c = c as u64;
        let mut words = bytes.chunks_exact(8);
        for w in &mut words {
            c = _mm_crc32_u64(c, u64::from_le_bytes(w.try_into().unwrap()));
        }
        let mut c = c as u32;
        for &b in words.remainder() {
            c = _mm_crc32_u8(c, b);
        }
        c
    }

    fn shift(t: &[[u32; 256]; 4], c: u32) -> u32 {
        t[0][(c & 0xff) as usize] ^ t[1][((c >> 8) & 0xff) as usize] ^ t[2][((c >> 16) & 0xff) as usize] ^ t[3][(c >> 24) as usize]
    }

    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn page(p: &[u8], t: &[[u32; 256]; 4]) -> (u32, bool) {
        let word = |i: usize| u64::from_le_bytes(p[i..i + 8].try_into().unwrap());
        let (mut a, mut b, mut c, mut or) = (!0u32 as u64, 0u64, 0u64, 0u64);
        for i in (0..STREAM).step_by(8) {
            let (x, y, z) = (word(i), word(STREAM + i), word(2 * STREAM + i));
            a = _mm_crc32_u64(a, x);
            b = _mm_crc32_u64(b, y);
            c = _mm_crc32_u64(c, z);
            or |= x | y | z;
        }
        // raw(r, X) = shift(r, |X|) ^ raw(0, X): stitch the streams together.
        let mut r = (shift(t, shift(t, a as u32) ^ b as u32) ^ c as u32) as u64;
        for i in (3 * STREAM..p.len()).step_by(8) {
            let x = word(i);
            r = _mm_crc32_u64(r, x);
            or |= x;
        }
        (!(r as u32), or == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PAGE_SIZE;

    #[test]
    fn known_values() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(!update_sw(!0, b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn page_matches_the_plain_crc() {
        let mut p = vec![0u8; PAGE_SIZE];
        assert_eq!(page(&p), (crc32c(&p), true));
        for seed in 0..64u64 {
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            for b in p.iter_mut() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = if seed % 4 == 0 { 0 } else { x as u8 };
            }
            p[(seed as usize * 61) % PAGE_SIZE] = seed as u8 | 1;
            assert_eq!(page(&p), (!update_sw(!0, &p), false), "seed {seed}");
        }
    }
}
