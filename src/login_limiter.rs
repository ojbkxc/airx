//! 登录限流 + 验证码（对齐 Go utils/login_limiter.go + utils/captcha.go）
//!
//! 策略：
//! - CaptchaThreshold：窗口内失败次数达到阈值后要求验证码（<0 禁用；0 强制）
//! - BanThreshold：达到阈值封禁 IP（0 不启用）
//! - AttemptsWindow/BanDuration 默认 5min/30min
//!
//! 验证码：Go 用 base64Captcha（字体渲染）。Rust 侧不引入字体栈，
//! 用 SVG 生成 4 位数字验证码（b64 内嵌 SVG），人机可读性等价。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 安全策略（从 config.app 读取阈值）
#[derive(Clone, Debug)]
pub struct SecurityPolicy {
    pub captcha_threshold: i64,
    pub ban_threshold: i64,
    pub attempts_window: Duration,
    pub ban_duration: Duration,
}

#[derive(Clone, Debug)]
struct CaptchaMeta {
    answer: String,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct BanRecord {
    expires_at: Instant,
}

/// 全局登录限流器（进程内存态，与 Go global.LoginLimiter 一致）
pub struct LoginLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    policy: SecurityPolicy,
    attempts: HashMap<String, Vec<Instant>>,
    captchas: HashMap<String, CaptchaMeta>,
    banned: HashMap<String, BanRecord>,
}

impl LoginLimiter {
    pub fn new(policy: SecurityPolicy) -> Self {
        Self {
            inner: Mutex::new(Inner {
                policy,
                attempts: HashMap::new(),
                captchas: HashMap::new(),
                banned: HashMap::new(),
            }),
        }
    }

    fn is_disabled(&self) -> bool {
        let p = &self.inner.lock().unwrap().policy;
        p.captcha_threshold < 0 && p.ban_threshold == 0
    }

    /// 记录失败尝试；达到 ban_threshold 封禁
    pub fn record_failed_attempt(&self, ip: &str) {
        if self.is_disabled() {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        if is_banned(&mut g.banned, ip) {
            return;
        }
        let now = Instant::now();
        let window_start = now.checked_sub(g.policy.attempts_window).unwrap_or(now);
        let mut valid: Vec<Instant> = g
            .attempts
            .get(ip)
            .map(|v| v.iter().filter(|t| **t > window_start).copied().collect())
            .unwrap_or_default();
        valid.push(now);
        if g.policy.ban_threshold > 0 && valid.len() >= g.policy.ban_threshold as usize {
            let ban_duration = g.policy.ban_duration;
            g.banned.insert(
                ip.to_string(),
                BanRecord {
                    expires_at: now + ban_duration,
                },
            );
            g.attempts.remove(ip);
            return;
        }
        g.attempts.insert(ip.to_string(), valid);
    }

    /// 登录成功后清除记录
    pub fn remove_attempts(&self, ip: &str) {
        self.inner.lock().unwrap().attempts.remove(ip);
    }

    /// 检查安全状态 → (banned, captcha_required)
    pub fn check_security_status(&self, ip: &str) -> (bool, bool) {
        if self.is_disabled() {
            return (false, false);
        }
        let mut g = self.inner.lock().unwrap();
        if is_banned(&mut g.banned, ip) {
            return (true, false);
        }
        let now = Instant::now();
        let window_start = now.checked_sub(g.policy.attempts_window).unwrap_or(now);
        let valid: Vec<Instant> = g
            .attempts
            .get(ip)
            .map(|v| v.iter().filter(|t| **t > window_start).copied().collect())
            .unwrap_or_default();
        if valid.is_empty() {
            g.attempts.remove(ip);
        } else {
            g.attempts.insert(ip.to_string(), valid.clone());
        }
        let required = match g.policy.captcha_threshold {
            0 => true,
            t => t > 0 && valid.len() >= t as usize,
        };
        (false, required)
    }

    /// 生成验证码 → (id, answer, b64 SVG)。过期 5 分钟。
    pub fn require_captcha(&self) -> Option<(String, String, String)> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let answer: String = (0..4).map(|_| rng.gen_range(0..10).to_string()).collect();
        let id = crate::utils::generate_token(&format!("cap{}", answer));
        let b64 = draw_captcha_svg(&answer);
        let mut g = self.inner.lock().unwrap();
        g.captchas.insert(
            id.clone(),
            CaptchaMeta {
                answer: answer.clone(),
                expires_at: Instant::now() + Duration::from_secs(5 * 60),
            },
        );
        // 顺带清理过期验证码（惰性清理，Go 是后台 ticker，语义等价）
        g.captchas.retain(|_, m| m.expires_at > Instant::now());
        Some((id, answer, b64))
    }

    /// 校验验证码（一次性）
    pub fn verify_captcha(&self, id: &str, answer: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.captchas.get(id) {
            Some(m) if m.expires_at > Instant::now() && m.answer == answer => {
                g.captchas.remove(id);
                true
            }
            Some(m) if m.expires_at <= Instant::now() => {
                g.captchas.remove(id);
                false
            }
            _ => false,
        }
    }
}

fn is_banned(banned: &mut HashMap<String, BanRecord>, ip: &str) -> bool {
    match banned.get(ip) {
        Some(r) if r.expires_at > Instant::now() => true,
        Some(_) => {
            banned.remove(ip);
            false
        }
        None => false,
    }
}

/// 渲染 SVG 验证码（干扰线 + 干扰点 + 随机色 + 轻微旋转），base64 data URI
fn draw_captcha_svg(answer: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let (w, h) = (150usize, 50usize);
    let mut svg = String::with_capacity(2048);
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\">"
    ));
    svg.push_str("<rect width=\"150\" height=\"50\" fill=\"#f0f0f4\"/>");
    // 干扰线
    for _ in 0..4 {
        let (x1, y1, x2, y2) = (
            rng.gen_range(0..w),
            rng.gen_range(0..h),
            rng.gen_range(0..w),
            rng.gen_range(0..h),
        );
        let c = rng.gen_range(120..200);
        svg.push_str(&format!(
            "<line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke=\"rgb({c},{c},{c})\" stroke-width=\"1\"/>"
        ));
    }
    // 数字（每位独立随机色/旋转/y 偏移）
    for (i, ch) in answer.chars().enumerate() {
        let x = 18 + i * 30;
        let y = 32 + rng.gen_range(-4..5);
        let rot = rng.gen_range(-25..26);
        let (r, g, b) = (
            rng.gen_range(20..90),
            rng.gen_range(20..90),
            rng.gen_range(60..140),
        );
        svg.push_str(&format!(
            "<text x=\"{x}\" y=\"{y}\" font-family=\"Arial, sans-serif\" font-size=\"28\" font-weight=\"bold\" fill=\"rgb({r},{g},{b})\" transform=\"rotate({rot} {x} {y})\">{ch}</text>"
        ));
    }
    // 干扰点
    for _ in 0..18 {
        let (cx, cy) = (rng.gen_range(0..w), rng.gen_range(0..h));
        let c = rng.gen_range(100..220);
        svg.push_str(&format!(
            "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"1.5\" fill=\"rgb({c},{c},{c})\"/>"
        ));
    }
    svg.push_str("</svg>");
    let b64 = crate::utils::b64_encode(svg.as_bytes());
    format!("data:image/svg+xml;base64,{}", b64)
}
