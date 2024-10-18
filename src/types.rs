use lazy_static::lazy_static;
use rocket::serde::Serialize;
use rocket::Shutdown;
use rocket_db_pools::{sqlx, Database};
use serde::Deserialize;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Database)]
#[database("sqlite_database")]
pub struct Db(pub SqlitePool);

#[derive(Debug, Deserialize, Serialize, FromForm, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Permission {
    pub gpt_gen: bool,
}

pub struct ServerState {
    pub db: SqlitePool,
    pub shutdown: Option<Shutdown>,
    pub cache: Vec<String>,
}

impl Permission {
    pub fn default() -> Permission {
        Permission { gpt_gen: false }
    }
}

#[derive(Debug, Deserialize, Serialize, FromForm, Clone)]
#[serde(crate = "rocket::serde")]
pub struct Features {
    pub gpt_writer: bool,
    pub traffic_gen: bool,
    pub add_buddy: bool,
    pub like_comment: bool,
}

impl Features {
    pub fn default() -> Features {
        Features {
            gpt_writer: false,
            traffic_gen: false,
            add_buddy: false,
            like_comment: false,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct FeaturesDB {
    pub gpt_writer: Option<bool>,
    pub traffic_gen: Option<bool>,
    pub add_buddy: Option<bool>,
    pub like_comment: Option<bool>,
}

#[derive(sqlx::FromRow)]
pub struct PermissionDB {
    pub gpt_gen: Option<bool>,
}

impl From<FeaturesDB> for Features {
    fn from(db: FeaturesDB) -> Self {
        Features {
            gpt_writer: db.gpt_writer.unwrap_or(false),
            traffic_gen: db.traffic_gen.unwrap_or(false),
            add_buddy: db.add_buddy.unwrap_or(false),
            like_comment: db.like_comment.unwrap_or(false),
        }
    }
}

impl From<PermissionDB> for Permission {
    fn from(db: PermissionDB) -> Self {
        Permission {
            gpt_gen: db.gpt_gen.unwrap_or(false),
        }
    }
}

#[derive(Serialize, FromForm, Debug)]
#[serde(crate = "rocket::serde")]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
    pub features: Features,
    pub permission: Permission,
}

#[derive(Deserialize)]
pub struct UserUpdateInfo {
    pub username: String,
    pub password: Option<String>,
    pub is_admin: Option<bool>,
    pub features: Option<Features>,
    pub permission: Option<Permission>,
}

#[derive(FromForm)]
pub struct User {
    pub username: String,
    pub password: String,
    pub is_admin: bool,
    pub features: Features,
    pub permission: Permission,
}

pub struct AuthenticatedUser {
    pub username: String,
    pub is_admin: bool,
}

pub struct LoginAttempt {
    pub count: u32,
    pub last_attempt: Instant,
}

lazy_static! {
    pub static ref LOGIN_ATTEMPTS: Mutex<HashMap<String, LoginAttempt>> =
        Mutex::new(HashMap::new());
}

pub const MAX_LOGIN_ATTEMPTS: u32 = 5;
// pub const LOCKOUT_DURATION: Duration = Duration::from_secs(15 * 60); // 15분
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(1); // 15분

#[derive(serde::Deserialize)]
pub struct ValidateSessionRequest {
    pub username: String,
}

#[derive(serde::Serialize)]
pub struct ValidateSessionResponse {
    pub is_valid: bool,
    pub message: String,
}
