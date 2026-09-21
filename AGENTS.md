# AIRX 项目开发者指南

## 项目概览

**AIRX** 是 [lejianwen/rustdesk-api](https://github.com/lejianwen/rustdesk-api) 的 Rust 全量重写 —— RustDesk 自建服务器的管理后端，与 AIGX 为姊妹项目（同仓库组织、同代码风格、同部署方式）。

核心价值：
- **直读现有库**：rusqlite(bundled) 直接读写旧 GORM 建的 SQLite，表结构零迁移零丢失
- **契约逐字节对齐 Go**：60+ 端点、响应格式、认证头、错误码完全一致，RustDesk 客户端与现有前端无缝切换
- **单二进制 + 前端产物**：musl 静态编译，alpine 运行镜像，SPA fallback 内置

## 技术栈

```yaml
后端：
  - Rust 2021 / axum 0.7 / tokio
  - rusqlite 0.31（bundled SQLite，单连接 Mutex）
  - bcrypt（旧库哈希兼容）/ serde_json

前端：
  - Vue 3 + Element Plus + Pinia
  - Vite（outDir: ../static）

数据库：
  - SQLite（表结构权威来源：src/db_schema.sql，从旧库 sqlite_master 导出）
  - 18 张表：users/peers/audit_conns/audit_files/login_logs/groups/device_groups/
    address_books/address_book_collections/address_book_collection_rules/
    user_tokens/user_thirds/oauths/tags/share_records/server_cmds/versions 等
```

## 仓库结构

```
├── src/
│   ├── main.rs           # 入口：build_router + 静态 fallback
│   ├── config.rs         # TOML ~/.airx/config.toml + AIRX_<SEC>__<FIELD> env + 全局快照
│   ├── db.rs             # rusqlite 连接 + 幂等建表
│   ├── db_schema.sql     # 权威表结构（旧库导出，IF NOT EXISTS 幂等）
│   ├── auth.rs           # BackendUserAuth / RustAuth（token 查 user_tokens 表）
│   ├── models.rs         # 表 struct
│   ├── web.rs            # SPA 静态服务 + fallback
│   └── api/
│       ├── client.rs     # 客户端 API /api/*（login/heartbeat/sysinfo/audit/ab/...）
│       ├── admin.rs      # 管理面登录/config/user/current/dashboard
│       ├── crud.rs       # 全量 CRUD（user/group/peer/address_book/oauth/audit/...）
│       ├── my.rs         # my.* 系列（只查自己）
│       ├── oauth.rs      # OAuth/OIDC + OauthCache
│       └── common.rs     # 响应封装
├── frontend/             # Vue3 源码（rustdesk-api-web + AIGX 玻璃拟态风格）
├── static/               # 前端 build 产物（提交入库）
├── airx-net/             # 预留 workspace 成员
└── Dockerfile            # 三阶段：node → rust(musl) → alpine
```

## API 契约（不可破坏）

### 两套分页，绝不混淆
- 客户端 `DataResponse`：`{"total": n, "data": [...]}`
- 管理面 `PageData`：`{"page": n, "total": n, "page_size": n, "list": [...]}`

### 响应封装
- 管理面成功：`{"code": 0, "message": "success", "data": ...}`（前端 axios 判 `code===0`）
- 客户端成功：同上格式
- 客户端错误：HTTP 400 `{"error": "..."}`
- 认证：管理面 `api-token` 头 → 403 `{code, message:"NeedLogin"|"NoAccess"}`；客户端 `Authorization: Bearer` → 401 `{"error":"Unauthorized"}`

### 关键约定
- 密码 bcrypt（旧库哈希兼容；不用 argon2）
- token 存 `user_tokens` 表，过期默认 7 天
- guid = `{group_id}-{user_id}-{collection_id}`
- AddressBook `tags`/`tag_colors` 在 `/api/ab` 是 JSON 字符串，管理面 CRUD 是数组
- 心跳 30s 节流；sysinfo 无则创建（user_id 从 login_logs 回查）
- rustdesk 系统命令：ID Server 6 条(target 21115) + Relay Server 13 条(target 21117) 内置

## 开发守则

### 三级自主权
- **Never**：修改表结构（db_schema.sql 是旧库导出的权威，加列必须同时验证旧库兼容）、改响应格式、动认证逻辑
- **Ask first**：新增依赖、改 CI、改 Dockerfile
- **自主**：bug 修复、新端点对齐 Go 行为、重构（保持契约不变）

### 验证闭环
1. `cargo fmt` + `cargo clippy --all-targets -- -D warnings` 全绿
2. 本地 `cargo run` + 旧库副本 curl 全链路（login → current → dashboard → client API）
3. push 后看 GitHub Actions（CI = fmt/clippy + workspace check + test + release build）

### 常见坑
- `MutexGuard<Connection>` 不能跨 `.await`（not Send）——先取数据再 await，或作用域包裹
- rusqlite 参数混类型必须 `rusqlite::params![]`，动态条件用 `Vec<&dyn ToSql>` + `.as_slice()`
- sqlite 里 `SELECT` 列序必须与 row mapper 索引严格对应（缺列 = 整行错位，数据"消失"）
- Go AutoTime 长格式 `"2026-09-18 09:08:24.570323984+00:00"` → 截前 19 位
- AutoJson：空串/解析失败 → `"[]"`
- 部署端口复用 nginx 上游 127.0.0.1:21414，切换无感
