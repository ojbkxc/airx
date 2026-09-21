//! AIRX 独立网络层 crate（预留 workspace 成员，对齐 AIGX aigx-net 结构）
//!
//! 当前为骨架：仅提供 workspace 编译验证与后续网络层功能的放置位置。
//! 预留的 socket 命令发送（hbbs/hbbr 控制命令）逻辑将在 P2 的 rustdesk/sendCmd 中使用。

/// 预留：网络层版本标识
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_ok() {
        assert!(!super::VERSION.is_empty());
    }
}
