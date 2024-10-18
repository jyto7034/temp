use serde::{Deserialize, Serialize};

use crate::types::{Features, Permission};

#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    pub message: String,
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub is_admin: Option<bool>,
    pub features: Option<Features>,
    pub permission: Option<Permission>,
}

#[derive(Serialize)]
pub struct ProxyResponse {
    pub proxy_list: Vec<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct DeleteAccountResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct UpdateUserResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}
