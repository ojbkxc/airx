//! AIRX 配置系统
//!
//! 照抄 AIGX：TOML 文件 + 环境变量覆盖 + 运行期热改（ConfigManager 用 tokio RwLock）。
//! 默认路径 ~/.airx/config.toml。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 顶层配置
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub app: AppSection,
    pub admin: AdminSection,
    pub rustdesk: RustdeskConfig,
}

/// 服务器监听配置
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 21414,
            data_dir: "~/.airx".into(),
        }
    }
}

/// App 段（对齐 Go config/config.go 的 app: 段）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppSection {
    pub web_client: i64,
    pub register: bool,
    pub register_status: i64,
    pub captcha_threshold: i64,
    pub ban_threshold: i64,
    pub show_swagger: i64,
    pub token_expire_secs: i64,
    pub web_sso: bool,
    pub disable_pwd_login: bool,
}

impl Default for AppSection {
    fn default() -> Self {
        Self {
            web_client: 1,
            register: false,
            register_status: 1,
            captcha_threshold: 3,
            ban_threshold: 0,
            show_swagger: 0,
            token_expire_secs: 7 * 24 * 3600, // 默认 7 天
            web_sso: true,
            disable_pwd_login: false,
        }
    }
}

/// Admin 段
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminSection {
    pub title: String,
    pub hello: String,
    pub hello_file: String,
    pub id_server_port: u16,
    pub relay_server_port: u16,
}

impl Default for AdminSection {
    fn default() -> Self {
        Self {
            title: "AIRX Admin".into(),
            hello: String::new(),
            hello_file: String::new(),
            id_server_port: 21116,
            relay_server_port: 21117,
        }
    }
}

/// Rustdesk 段（对齐 Go config/rustdesk.go）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RustdeskConfig {
    pub id_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub key: String,
    pub key_file: String,
    pub personal: i64,
    pub webclient_magic_queryonline: i64,
    pub ws_host: String,
}

impl Default for RustdeskConfig {
    fn default() -> Self {
        Self {
            id_server: String::new(),
            relay_server: String::new(),
            api_server: String::new(),
            key: String::new(),
            key_file: String::new(),
            personal: 1,
            webclient_magic_queryonline: 0,
            ws_host: String::new(),
        }
    }
}

/// 配置管理器：启动加载 + 运行期热改 + 环境变量覆盖
pub struct ConfigManager {
    path: PathBuf,
    inner: RwLock<AppConfig>,
}

impl ConfigManager {
    pub async fn new(path: Option<PathBuf>) -> Self {
        let path = path.unwrap_or_else(default_config_path);
        let config = load_or_create(&path);
        let config = apply_env_overrides(config);
        Self {
            path,
            inner: RwLock::new(config),
        }
    }

    pub async fn get(&self) -> AppConfig {
        self.inner.read().await.clone()
    }

    pub async fn update(&self, config: AppConfig) -> anyhow::Result<()> {
        let text = toml::to_string_pretty(&config)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, text)?;
        *self.inner.write().await = config;
        Ok(())
    }
}

/// 展开 ~ 为 home 目录
pub fn expand_path(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

fn default_config_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".airx").join("config.toml")
}

fn load_or_create(path: &PathBuf) -> AppConfig {
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str::<AppConfig>(&text) {
                Ok(cfg) => return cfg,
                Err(e) => {
                    tracing::warn!("config.toml parse error: {e}, using defaults");
                }
            },
            Err(e) => {
                tracing::warn!("config.toml read error: {e}, using defaults");
            }
        }
    }
    let cfg = AppConfig::default();
    // 写入默认配置
    if let Ok(text) = toml::to_string_pretty(&cfg) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, text);
    }
    cfg
}

/// 环境变量覆盖：AIRX_<SECTION>__<FIELD>（双下划线分隔 section 与 field）
fn apply_env_overrides(mut config: AppConfig) -> AppConfig {
    if let Ok(v) = std::env::var("AIRX_SERVER__HOST") {
        config.server.host = v;
    }
    if let Ok(v) = std::env::var("AIRX_SERVER__PORT") {
        if let Ok(p) = v.parse::<u16>() {
            config.server.port = p;
        }
    }
    if let Ok(v) = std::env::var("AIRX_SERVER__DATA_DIR") {
        config.server.data_dir = v;
    }
    // Rustdesk 段覆盖（部署时注入 key/id/relay/api）
    if let Ok(v) = std::env::var("AIRX_RUSTDESK__KEY") {
        config.rustdesk.key = v;
    }
    if let Ok(v) = std::env::var("AIRX_RUSTDESK__ID_SERVER") {
        config.rustdesk.id_server = v;
    }
    if let Ok(v) = std::env::var("AIRX_RUSTDESK__RELAY_SERVER") {
        config.rustdesk.relay_server = v;
    }
    if let Ok(v) = std::env::var("AIRX_RUSTDESK__API_SERVER") {
        config.rustdesk.api_server = v;
    }
    if let Ok(v) = std::env::var("AIRX_ADMIN__TITLE") {
        config.admin.title = v;
    }
    config
}

/// 全局配置引用（供非 async 路径使用；与 AIGX 的 config::xxx 快照模式一致）
static SNAPSHOT: std::sync::OnceLock<Arc<AppConfig>> = std::sync::OnceLock::new();

/// 快照当前配置（进程启动后调用一次）
pub fn set_snapshot(cfg: Arc<AppConfig>) {
    let _ = SNAPSHOT.set(cfg);
}

/// 读取配置快照（无快照时返回默认值）
pub fn snapshot() -> Arc<AppConfig> {
    SNAPSHOT
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(AppConfig::default()))
}
