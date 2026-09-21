//! AIRX 数据模型（对齐 Go model/ 目录，18 张表）

use serde::{Deserialize, Serialize};

/// 用户状态
pub const STATUS_ENABLE: i64 = 1;
pub const STATUS_DISABLED: i64 = 2;

/// 普通用户可见路由名（对齐 Go model.UserRouteNames）
pub fn user_route_names() -> Vec<String> {
    vec![
        "MyTagList".to_string(),
        "MyAddressBookList".to_string(),
        "MyInfo".to_string(),
        "MyAddressBookCollection".to_string(),
        "MyPeer".to_string(),
        "MyShareRecordList".to_string(),
        "MyLoginLog".to_string(),
    ]
}

/// 管理员路由名
pub fn admin_route_names() -> Vec<String> {
    vec!["*".to_string()]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub nickname: String,
    pub avatar: String,
    pub group_id: i64,
    pub is_admin: bool,
    pub status: i64,
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Default for User {
    fn default() -> Self {
        Self {
            id: 0,
            username: String::new(),
            email: String::new(),
            password: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            group_id: 0,
            is_admin: false,
            status: STATUS_ENABLE,
            remark: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    pub fn is_enabled(&self) -> bool {
        self.status == STATUS_ENABLE
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct UserToken {
    pub id: i64,
    pub user_id: i64,
    pub device_uuid: String,
    pub device_id: String,
    pub token: String,
    pub expired_at: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Peer {
    pub row_id: i64,
    pub id: String,
    pub cpu: String,
    pub hostname: String,
    pub memory: String,
    pub os: String,
    pub username: String,
    pub uuid: String,
    pub version: String,
    pub user_id: i64,
    pub last_online_time: i64,
    pub last_online_ip: String,
    pub group_id: i64,
    pub alias: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AuditConn {
    pub id: i64,
    pub action: String,
    pub conn_id: i64,
    pub peer_id: String,
    pub from_peer: String,
    pub from_name: String,
    pub ip: String,
    pub session_id: String,
    #[serde(rename = "type")]
    pub type_: i64,
    pub uuid: String,
    pub close_time: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AuditFile {
    pub id: i64,
    pub from_peer: String,
    pub info: String,
    pub is_file: bool,
    pub path: String,
    pub peer_id: String,
    #[serde(rename = "type")]
    pub type_: i64,
    pub uuid: String,
    pub ip: String,
    pub num: i64,
    pub from_name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct LoginLog {
    pub id: i64,
    pub user_id: i64,
    pub client: String,
    pub device_id: String,
    pub uuid: String,
    pub ip: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub platform: String,
    pub user_token_id: i64,
    pub is_deleted: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            type_: 1,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct DeviceGroup {
    pub id: i64,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AddressBook {
    pub row_id: i64,
    pub id: String,
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub alias: String,
    pub platform: String,
    pub tags: String, // JSON 字符串
    pub hash: String,
    pub user_id: i64,
    #[serde(rename = "forceAlwaysRelay")]
    pub force_always_relay: bool,
    #[serde(rename = "rdpPort")]
    pub rdp_port: String,
    #[serde(rename = "rdpUsername")]
    pub rdp_username: String,
    pub online: bool,
    #[serde(rename = "loginName")]
    pub login_name: String,
    #[serde(rename = "sameServer")]
    pub same_server: bool,
    pub collection_id: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Default for AddressBook {
    fn default() -> Self {
        Self {
            row_id: 0,
            id: String::new(),
            username: String::new(),
            password: String::new(),
            hostname: String::new(),
            alias: String::new(),
            platform: String::new(),
            tags: "[]".to_string(),
            hash: String::new(),
            user_id: 0,
            force_always_relay: false,
            rdp_port: String::new(),
            rdp_username: String::new(),
            online: false,
            login_name: String::new(),
            same_server: false,
            collection_id: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AddressBookCollection {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AddressBookCollectionRule {
    pub id: i64,
    pub user_id: i64,
    pub collection_id: i64,
    pub rule: i64, // 1=读 2=读写 3=完全控制
    #[serde(rename = "type")]
    pub type_: i64, // 1=个人 2=群组
    pub to_id: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Default for AddressBookCollectionRule {
    fn default() -> Self {
        Self {
            id: 0,
            user_id: 0,
            collection_id: 0,
            rule: 0,
            type_: 1,
            to_id: 0,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Tag {
    pub id: i64,
    pub name: String,
    pub user_id: i64,
    pub color: i64,
    pub collection_id: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Oauth {
    pub id: i64,
    pub op: String,
    pub oauth_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub auto_register: bool,
    pub scopes: String,
    pub issuer: String,
    pub pkce_enable: bool,
    pub pkce_method: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct UserThird {
    pub id: i64,
    pub user_id: i64,
    pub open_id: String,
    pub name: String,
    pub username: String,
    pub email: String,
    pub verified_email: bool,
    pub picture: String,
    pub union_id: String,
    pub third_type: String,
    pub oauth_type: String,
    pub op: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ShareRecord {
    pub id: i64,
    pub user_id: i64,
    pub peer_id: String,
    pub share_token: String,
    pub password_type: String,
    pub password: String,
    pub expire: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct ServerCmd {
    pub id: i64,
    pub cmd: String,
    pub alias: String,
    pub option: String,
    pub explain: String,
    pub target: String,
    pub created_at: String,
    pub updated_at: String,
}
