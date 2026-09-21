# AIRX — 多阶段构建：前端 → 后端 → 精简运行镜像
# 运行时：alpine（musl 静态二进制 + 前端产物 + 数据卷）

# ── 阶段 1：前端构建 ──────────────────────────────────────────
FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
# static/ 产物直接落到仓库根的 static/（vite outDir: ../static）
RUN npm run build

# ── 阶段 2：Rust 后端构建（musl 静态链接）────────────────────
FROM rust:1-alpine AS backend
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY airx-net ./airx-net
# 前端产物在编译期不嵌入（运行时读取 ./static），仅需编译 Rust
#
# 编译期加固：不可执行栈(noexecstack)；musl 目标默认即静态链接
# （rust:1-alpine 的 host triple 是 musl），无需显式 crt-static——
# 显式设置会连同 proc-macro 也按 musl 目标编译，而 proc-macro
# 必须跑在构建宿主上，直接报 "cannot produce proc-macro"。
# CFLAGS 让 cc crate 编译 bundled SQLite(C 代码) 时开启栈保护。
ENV RUSTFLAGS="-C link-arg=-Wl,-z,noexecstack" \
    CFLAGS="-fstack-protector-strong"
RUN cargo build --release --locked

# ── 阶段 3：运行镜像 ──────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -S airx && adduser -S airx -G airx
WORKDIR /opt/airx
COPY --from=backend /app/target/release/airx /opt/airx/airx
COPY --from=frontend /app/static /opt/airx/static
# 数据目录（config.toml / rustdeskapi.db）由挂载卷持久化；
# 直接复用旧 Go 容器的 /opt/rustdesk-api/data 卷（同一 SQLite 库）
RUN mkdir -p /home/airx/.airx && chown -R airx:airx /opt/airx /home/airx/.airx
# 容器内绑定 0.0.0.0（默认 127.0.0.1 无法从宿主机访问），端口可用
# AIRX_SERVER__PORT 覆盖；data_dir 固定到卷内路径
ENV AIRX_SERVER__HOST=0.0.0.0 \
    AIRX_SERVER__PORT=8080 \
    AIRX_SERVER__DATA_DIR=/home/airx/.airx
USER airx
VOLUME ["/home/airx/.airx"]
EXPOSE 8080
ENTRYPOINT ["/opt/airx/airx"]
