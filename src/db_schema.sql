-- airx Rust 后端数据库 schema
-- 权威来源：lejianwen/rustdesk-api 旧库 sqlite_master 导出（保持 GORM 建表结构不变）
-- 执行方式：启动时对 SQLite 逐个执行（IF NOT EXISTS 幂等）

CREATE TABLE IF NOT EXISTS `address_book_collection_rules` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`rule` integer NOT NULL DEFAULT 0,`type` integer NOT NULL DEFAULT 1,`to_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `address_book_collections` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `address_books` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "0",`username` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`alias` text NOT NULL DEFAULT "",`platform` text NOT NULL DEFAULT "",`tags` text NOT NULL,`hash` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`force_always_relay` numeric NOT NULL DEFAULT false,`rdp_port` text NOT NULL DEFAULT "",`rdp_username` text NOT NULL DEFAULT "",`online` numeric NOT NULL DEFAULT false,`login_name` text NOT NULL DEFAULT "",`same_server` numeric NOT NULL DEFAULT false,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `audit_conns` (`id` integer PRIMARY KEY AUTOINCREMENT,`action` text NOT NULL DEFAULT "",`conn_id` integer NOT NULL DEFAULT 0,`peer_id` text NOT NULL DEFAULT "",`from_peer` text NOT NULL DEFAULT "",`from_name` text NOT NULL DEFAULT "",`ip` text NOT NULL DEFAULT "",`session_id` text NOT NULL DEFAULT "",`type` integer NOT NULL DEFAULT 0,`uuid` text NOT NULL DEFAULT "",`close_time` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `audit_files` (`id` integer PRIMARY KEY AUTOINCREMENT,`from_peer` text NOT NULL DEFAULT "",`info` text NOT NULL DEFAULT "",`is_file` numeric NOT NULL DEFAULT false,`path` text NOT NULL DEFAULT "",`peer_id` text NOT NULL DEFAULT "",`type` integer NOT NULL DEFAULT 0,`uuid` text NOT NULL DEFAULT "",`ip` text NOT NULL DEFAULT "",`num` integer NOT NULL DEFAULT 0,`from_name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `device_groups` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `groups` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`type` integer NOT NULL DEFAULT 1,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `login_logs` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`client` text,`device_id` text,`uuid` text,`ip` text,`type` text,`platform` text,`user_token_id` integer NOT NULL DEFAULT 0,`is_deleted` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `oauths` (`id` integer PRIMARY KEY AUTOINCREMENT,`op` text,`oauth_type` text,`client_id` text,`client_secret` text,`auto_register` numeric,`scopes` text,`issuer` text,`pkce_enable` numeric,`pkce_method` text,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `peers` (`row_id` integer PRIMARY KEY AUTOINCREMENT,`id` text NOT NULL DEFAULT "",`cpu` text NOT NULL DEFAULT "",`hostname` text NOT NULL DEFAULT "",`memory` text NOT NULL DEFAULT "",`os` text NOT NULL DEFAULT "",`username` text NOT NULL DEFAULT "",`uuid` text NOT NULL DEFAULT "",`version` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`last_online_time` integer NOT NULL DEFAULT 0,`last_online_ip` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`alias` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `server_cmds` (`id` integer PRIMARY KEY AUTOINCREMENT,`cmd` text NOT NULL DEFAULT "",`alias` text NOT NULL DEFAULT "",`option` text NOT NULL DEFAULT "",`explain` text NOT NULL DEFAULT "",`target` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `share_records` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`peer_id` text NOT NULL DEFAULT "",`share_token` text NOT NULL DEFAULT "",`password_type` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`expire` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `tags` (`id` integer PRIMARY KEY AUTOINCREMENT,`name` text NOT NULL DEFAULT "",`user_id` integer NOT NULL DEFAULT 0,`color` integer NOT NULL DEFAULT 0,`collection_id` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `user_thirds` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL,`open_id` text NOT NULL,`name` text,`username` text,`email` text,`verified_email` numeric,`picture` text,`union_id` text NOT NULL DEFAULT "",`third_type` text NOT NULL DEFAULT "",`oauth_type` text NOT NULL DEFAULT "",`op` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `user_tokens` (`id` integer PRIMARY KEY AUTOINCREMENT,`user_id` integer NOT NULL DEFAULT 0,`device_uuid` text DEFAULT "",`device_id` text DEFAULT "",`token` text NOT NULL DEFAULT "",`expired_at` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `users` (`id` integer PRIMARY KEY AUTOINCREMENT,`username` text NOT NULL DEFAULT "",`email` text NOT NULL DEFAULT "",`password` text NOT NULL DEFAULT "",`nickname` text NOT NULL DEFAULT "",`avatar` text NOT NULL DEFAULT "",`group_id` integer NOT NULL DEFAULT 0,`is_admin` numeric NOT NULL DEFAULT false,`status` integer NOT NULL DEFAULT 1,`remark` text NOT NULL DEFAULT "",`created_at` timestamp,`updated_at` timestamp);

CREATE TABLE IF NOT EXISTS `versions` (`id` integer PRIMARY KEY AUTOINCREMENT,`version` integer NOT NULL DEFAULT 0,`created_at` timestamp,`updated_at` timestamp);

CREATE INDEX IF NOT EXISTS `idx_address_book_collection_rules_collection_id` ON `address_book_collection_rules`(`collection_id`);

CREATE INDEX IF NOT EXISTS `idx_address_book_collections_user_id` ON `address_book_collections`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_address_books_collection_id` ON `address_books`(`collection_id`);

CREATE INDEX IF NOT EXISTS `idx_address_books_id` ON `address_books`(`id`);

CREATE INDEX IF NOT EXISTS `idx_address_books_user_id` ON `address_books`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_audit_conns_conn_id` ON `audit_conns`(`conn_id`);

CREATE INDEX IF NOT EXISTS `idx_audit_conns_peer_id` ON `audit_conns`(`peer_id`);

CREATE INDEX IF NOT EXISTS `idx_audit_files_from_peer` ON `audit_files`(`from_peer`);

CREATE INDEX IF NOT EXISTS `idx_audit_files_peer_id` ON `audit_files`(`peer_id`);

CREATE INDEX IF NOT EXISTS `idx_peers_alias` ON `peers`(`alias`);

CREATE INDEX IF NOT EXISTS `idx_peers_group_id` ON `peers`(`group_id`);

CREATE INDEX IF NOT EXISTS `idx_peers_id` ON `peers`(`id`);

CREATE INDEX IF NOT EXISTS `idx_peers_user_id` ON `peers`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_peers_uuid` ON `peers`(`uuid`);

CREATE INDEX IF NOT EXISTS `idx_share_records_peer_id` ON `share_records`(`peer_id`);

CREATE INDEX IF NOT EXISTS `idx_share_records_share_token` ON `share_records`(`share_token`);

CREATE INDEX IF NOT EXISTS `idx_share_records_user_id` ON `share_records`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_tags_collection_id` ON `tags`(`collection_id`);

CREATE INDEX IF NOT EXISTS `idx_tags_user_id` ON `tags`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_user_thirds_open_id` ON `user_thirds`(`open_id`);

CREATE INDEX IF NOT EXISTS `idx_user_thirds_user_id` ON `user_thirds`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_user_tokens_token` ON `user_tokens`(`token`);

CREATE INDEX IF NOT EXISTS `idx_user_tokens_user_id` ON `user_tokens`(`user_id`);

CREATE INDEX IF NOT EXISTS `idx_users_email` ON `users`(`email`);

CREATE INDEX IF NOT EXISTS `idx_users_group_id` ON `users`(`group_id`);

CREATE UNIQUE INDEX IF NOT EXISTS `idx_users_username` ON `users`(`username`);

