use crate::server;
use crate::types::{AuthenticatedUser, Db, Features, Permission, User, UserInfo, UserUpdateInfo};
use rocket::form::Form;
use rocket::http::Status;
use rocket::serde::json::Json;
use sqlx::SqlitePool;

pub async fn update_user(
    db: &SqlitePool,
    username: &String,
    password: Option<String>,
    is_admin: Option<bool>,
    features: Option<Features>,
    permission: Option<Permission>,
) -> Result<String, Status> {
    // TODO: password 바꾸는 코드 작성해야함.
    // server.rs 의 update_user 변경
    let user_info = UserUpdateInfo {
        username: username.clone(),
        password,
        is_admin,
        features,
        permission,
    };

    match server::update_user(
        AuthenticatedUser {
            username: "admin".to_string(),
            is_admin: true,
        },
        Json(user_info),
        &Db(db.clone()),
    )
    .await
    {
        Ok(message) => Ok(message.message.clone()),
        Err(e) => Err(e),
    }
}

pub async fn delete_account(db: &SqlitePool, username: String) -> Result<String, Status> {
    match server::delete_account(
        AuthenticatedUser {
            username: "admin".to_string(),
            is_admin: true,
        },
        &username,
        None,
        &Db(db.clone()),
    )
    .await
    {
        Ok(_) => Ok("Deleted.".to_string()),
        Err(e) => Err(e),
    }
}

pub async fn get_user_list(db: &SqlitePool) -> Result<Vec<UserInfo>, Status> {
    match server::get_user_list(
        AuthenticatedUser {
            username: "admin".to_string(),
            is_admin: true,
        },
        &Db(db.clone()),
    )
    .await
    {
        Ok(Json(users)) => Ok(users),
        Err(e) => Err(e),
    }
}

pub async fn register(
    db: &SqlitePool,
    username: String,
    password: String,
    is_admin: bool,
    features: Features,
    permission: Permission,
) -> Result<String, Status> {
    let user = User {
        username,
        password,
        is_admin,
        features,
        permission,
    };

    match server::register(
        AuthenticatedUser {
            username: "admin".to_string(),
            is_admin: true,
        },
        Form::from(user),
        &Db(db.clone()),
    )
    .await
    {
        Ok(message) => Ok(message.message.clone()),
        Err(e) => Err(e),
    }
}