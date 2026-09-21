//! TOTP 两步验证（RFC 6238）——管理面登录增强（Go 原版未实现，属 AIRX 补足项）。
//!
//! 自研 SHA-1（RFC 3174）而非引第三方 crate：现有依赖（sha2 只含 SHA-2 家族）
//! 不含 SHA-1；RFC 3174 约 60 行纯函数无 unsafe，用官方测试向量锁死正确性。
//! TOTP 依赖 HMAC 的 PRF 性质，SHA-1 碰撞攻击不影响该用途（RFC 6238 默认算法）。
//!
//! 仅作用于管理面（/api/admin/login）；客户端 /api/login（RustDesk 机器客户端）
//! 不做 TFA，避免破坏真实客户端连接。

use rand::RngCore;

// ── SHA-1（RFC 3174）────────────────────────────────────────────────

/// SHA-1 哈希（仅用于 TOTP 的 HMAC 构造）。
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let ml = (msg.len() as u64) * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&ml.to_be_bytes());

    for block in data.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ── HMAC-SHA1（RFC 2104）────────────────────────────────────────────

/// HMAC-SHA1：key 长于块（64 字节）时先哈希；短于则零填充。
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let key = if key.len() > 64 {
        let k = sha1(key);
        let mut padded = k.to_vec();
        padded.resize(64, 0);
        padded
    } else {
        let mut padded = key.to_vec();
        padded.resize(64, 0);
        padded
    };

    let mut inner = Vec::with_capacity(64 + msg.len());
    for b in key.iter() {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(msg);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    for b in key.iter() {
        outer.push(b ^ 0x5C);
    }
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

// ── TOTP（RFC 6238）─────────────────────────────────────────────────

/// 时间步长（秒）——RFC 6238 推荐 30s。
pub const TOTP_PERIOD: u64 = 30;

/// 在指定计数器（时间步）生成 TOTP 码（dynamic truncation，RFC 4226 §5.3）。
pub fn totp_at(secret: &[u8], counter: u64, digits: usize) -> String {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = (mac[19] & 0x0F) as usize;
    let code = ((mac[offset] as u32 & 0x7F) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus = 10u32.pow(digits as u32);
    format!("{:0width$}", code % modulus, width = digits)
}

/// 当前 Unix 时间戳（秒）。
pub fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 验证 TOTP 码——允许 ±window 个时间步的时钟偏移（常量时间比较）。
pub fn verify(secret: &[u8], code: &str, window: u64) -> bool {
    let now_step = unix_now() / TOTP_PERIOD;
    let eq_const = |a: &str, b: &str| -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let mut diff = (a.len() ^ b.len()) as u8;
        for i in 0..a.len().max(b.len()) {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            diff |= x ^ y;
        }
        diff == 0
    };
    for delta in 0..=window {
        for step in [now_step + delta, now_step - delta.min(now_step)] {
            if eq_const(&totp_at(secret, step, 6), code) {
                return true;
            }
        }
    }
    false
}

// ── Base32（RFC 4648，无填充）——authenticator 的 secret 编码 ──

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 编码（无填充，otpauth secret 惯例）。
pub fn base32_encode(data: &[u8]) -> String {
    let n = (data.len() * 8).div_ceil(5);
    let mut out = String::with_capacity(n);
    let mut bit_pos = 0usize;
    for _ in 0..n {
        let mut val = 0u8;
        for b in 0..5 {
            let idx = bit_pos + b;
            let bit = if idx < data.len() * 8 {
                (data[idx / 8] >> (7 - idx % 8)) & 1
            } else {
                0
            };
            val = (val << 1) | bit;
        }
        out.push(B32_ALPHABET[val as usize] as char);
        bit_pos += 5;
    }
    out
}

/// Base32 解码（忽略大小写，容忍无填充输入）。
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=').to_ascii_uppercase();
    let mut bits: u64 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for ch in s.bytes() {
        let v = B32_ALPHABET.iter().position(|&c| c == ch)? as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    Some(out)
}

// ── 业务辅助 ────────────────────────────────────────────────────────

/// 生成新 secret：20 字节随机数（160 bit 熵，RFC 4226 推荐）→ base32。
pub fn generate_secret() -> String {
    let mut raw = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut raw);
    base32_encode(&raw)
}

/// otpauth:// URL（Google Authenticator / Aegis 等扫码识别格式）。
pub fn otpauth_url(secret: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&period=30&digits=6",
        url_encode(issuer),
        url_encode(account),
        secret,
        url_encode(issuer),
    )
}

/// URL 百分号编码（otpauth 路径用）。
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_nist_vectors() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(&vec![0x61u8; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_vectors() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn totp_rfc6238_appendix_b() {
        let secret = b"12345678901234567890";
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, expected) in cases {
            assert_eq!(totp_at(secret, t / 30, 8), expected, "T={t}");
        }
    }

    #[test]
    fn totp_verify_window() {
        let secret = b"any-secret-for-test";
        let now_step = unix_now() / TOTP_PERIOD;
        let code = totp_at(secret, now_step, 6);
        assert!(verify(secret, &code, 0));
        let bad = format!(
            "{:06}",
            code.parse::<u32>().unwrap().wrapping_add(1) % 1_000_000
        );
        assert!(!verify(secret, &bad, 0));
        let next_code = totp_at(secret, now_step + 1, 6);
        assert!(verify(secret, &next_code, 1));
    }

    #[test]
    fn base32_roundtrip() {
        for data in [b"".as_slice(), b"f".as_slice(), b"foobar".as_slice()] {
            let enc = base32_encode(data);
            assert_eq!(base32_decode(&enc).unwrap(), data, "roundtrip {enc}");
        }
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
    }

    #[test]
    fn secret_format() {
        let s = generate_secret();
        // 20 字节 → 32 字符 base32
        assert_eq!(s.len(), 32);
        assert!(s.bytes().all(|b| B32_ALPHABET.contains(&b)));
        assert!(base32_decode(&s).is_some());
    }

    #[test]
    fn otpauth_url_format() {
        let url = otpauth_url("MFRGGZDF", "admin", "AIRX Admin");
        assert!(url.starts_with("otpauth://totp/AIRX%20Admin:admin?secret=MFRGGZDF&issuer=AIRX%20Admin&period=30&digits=6"));
    }
}
