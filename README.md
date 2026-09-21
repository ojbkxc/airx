# AIRX

**RustDesk 自建服务器管理后端** —— [lejianwen/rustdesk-api](https://github.com/lejianwen/rustdesk-api) 的 Rust 全量重写，AIGX 姊妹项目。

## 特性

- **Rust + axum 0.7 + rusqlite**：单二进制，musl 静态编译，alpine 运行镜像
- **直读现有库**：表结构零迁移，旧 GORM 建的 SQLite 原样复用（`src/db_schema.sql` 为权威）
- **契约逐字节对齐 Go 原版**：RustDesk 客户端、Web Client、管理前端无缝切换
  - 客户端 API 40 端点：login / heartbeat / sysinfo / audit / address book（含 guid 权限体系）/ server-config …
  - 管理面 67 handler：用户/分组/设备/地址簿/OAuth/审计/系统命令 …
  - my.* 个人数据系列
- **内置 SPA**：Vue3 + Element Plus 管理前端（AIGX 玻璃拟态风格）随二进制同发
- **直连 hbbs/hbbr**：系统命令下发（19 条内置 + TCP sendCmd）

## 快速开始

```bash
# 本地开发
cargo run   # 默认 127.0.0.1:21414，数据目录 ~/.airx

# Docker
docker build -t airx .
docker run -d -p 21414:8080 \
  -v /opt/rustdesk-api/data:/home/airx/.airx \
  -e AIRX_RUSTDESK__ID_SERVER=your.host:21116 \
  -e AIRX_RUSTDESK__RELAY_SERVER=your.host:21117 \
  -e AIRX_RUSTDESK__API_SERVER=http://your.host:21114 \
  -e AIRX_RUSTDESK__KEY=<你的密钥> \
  airx
```

管理面板：`http://127.0.0.1:21414/`（默认账号见 users 表）

## 配置

TOML（`~/.airx/config.toml`）+ 环境变量 `AIRX_<SEC>__<FIELD>`，如：

```toml
[server]
host = "0.0.0.0"
port = 21414
data_dir = "/data"

[rustdesk]
id_server = "your.host:21116"
relay_server = "your.host:21117"
api_server = "http://your.host:21114"
key = "your-key"
```

## 从 Go 版切换

1. 备份旧库：`docker cp rustdesk-api:/app/data/rustdeskapi.db /opt/airx/backup/`
2. 启动 airx 容器挂载同一数据目录（见上）
3. nginx 上游不变（`127.0.0.1:21414`），无感切换
4. 回滚：`docker start rustdesk-api`

## License

同上游 rustdesk-api（AGPL-3.0）
