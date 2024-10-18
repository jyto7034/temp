use crate::respone::DeleteAccountResponse;
use crate::respone::LoginResponse;
use crate::respone::LogoutResponse;
use crate::respone::ProxyResponse;
use crate::respone::RegisterResponse;
use crate::respone::UpdateUserResponse;
use crate::types::*;
use crate::utils::*;
use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use rocket::form::Form;
use rocket::http::SameSite;
use rocket::http::Status;
use rocket::http::{Cookie, CookieJar};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::Json;
use rocket::State;
use rocket_db_pools::sqlx;
use std::sync::Arc;
use tokio::sync::Mutex;

// TODO: attemp wait time 수정

// pub struct ServerStateGuard(pub Arc<Mutex<ServerState>>);

// #[rocket::async_trait]
// impl<'r> FromRequest<'r> for ServerStateGuard {
//     type Error = ();

//     async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
//         match request.guard::<&State<Arc<Mutex<ServerState>>>>().await {
//             Outcome::Success(state) => Outcome::Success(ServerStateGuard(state.inner().clone())),
//             _ => Outcome::Error((rocket::http::Status::InternalServerError, ())),
//         }
//     }
// }

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        if let Some(cookie) = cookies.get_private("user_id") {
            let db = request.guard::<&Db>().await.succeeded().unwrap();
            let session_token = cookie.value();
            println!("{session_token}");

            if let Some(user_id) = extract_user_id_from_token(session_token) {
                if let Ok(Some(user)) =
                    sqlx::query!("SELECT username, is_admin FROM users WHERE id = ?", user_id)
                        .fetch_optional(&db.0)
                        .await
                {
                    if let (Some(is_admin), Some(username)) = (user.is_admin, user.username) {
                        return Outcome::Success(AuthenticatedUser { username, is_admin });
                    } else {
                        return Outcome::Error((Status::InternalServerError, ()));
                    }
                }
            }
        }
        Outcome::Error((Status::Unauthorized, ()))
    }
}

#[put("/update_user", data = "<user_info>")]
pub async fn update_user(
    auth_user: AuthenticatedUser,
    user_info: Json<UserUpdateInfo>,
    db: &Db,
) -> Result<Json<UpdateUserResponse>, Status> {
    // 관리자 권한 확인
    if !auth_user.is_admin {
        return Err(Status::Forbidden);
    }

    let user_info = user_info.into_inner();

    // 트랜잭션 시작
    let mut tx = db.begin().await.map_err(|_| Status::InternalServerError)?;

    // 사용자 존재 여부 확인
    let user_exists = sqlx::query!(
        "SELECT id FROM users WHERE username = ?",
        user_info.username
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Status::InternalServerError)?;

    if user_exists.is_none() {
        return Err(Status::NotFound);
    }

    // 패스워드 업데이트 (만약 제공되었다면)
    if let Some(new_password) = user_info.password {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map_err(|_| Status::InternalServerError)?
            .to_string();

        sqlx::query!(
            "UPDATE users SET password = ? WHERE username = ?",
            password_hash,
            user_info.username
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;
    }

    // 관리자 상태 업데이트 (만약 제공되었다면)
    if let Some(is_admin) = user_info.is_admin {
        sqlx::query!(
            "UPDATE users SET is_admin = ? WHERE username = ?",
            is_admin,
            user_info.username
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;
    }

    // 기능 접근 권한 업데이트 (만약 제공되었다면)
    if let Some(features) = user_info.features {
        sqlx::query!(
            "UPDATE features SET gpt_writer = ?, traffic_gen = ?, add_buddy = ?, like_comment = ? WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            features.gpt_writer, features.traffic_gen, features.add_buddy, features.like_comment, user_info.username
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;
    }

    // 권한 업데이트 (만약 제공되었다면)
    if let Some(permission) = user_info.permission {
        sqlx::query!(
            "UPDATE permissions SET gpt_gen = ? WHERE user_id = (SELECT id FROM users WHERE username = ?)",
            permission.gpt_gen, user_info.username
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| Status::InternalServerError)?;
    }

    // 트랜잭션 커밋
    tx.commit().await.map_err(|_| Status::InternalServerError)?;

    Ok(Json(UpdateUserResponse {
        message: format!("User {} updated successfully", user_info.username),
    }))
}
#[post("/delete_account/<username>")]
pub async fn delete_account(
    auth_user: AuthenticatedUser,
    username: &str,
    cookies: Option<&CookieJar<'_>>,
    db: &Db,
) -> Result<Json<DeleteAccountResponse>, Status> {
    if !auth_user.is_admin {
        return Err(Status::Forbidden);
    }

    // 변경해야함.
    if username == "admin" {
        return Err(Status::Forbidden);
    }

    let mut transaction = db.begin().await.map_err(|_| Status::InternalServerError)?;

    sqlx::query!(
        "DELETE FROM features WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        username
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| Status::InternalServerError)?;

    sqlx::query!(
        "DELETE FROM permissions WHERE user_id = (SELECT id FROM users WHERE username = ?)",
        username
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| Status::InternalServerError)?;

    let result = sqlx::query!("DELETE FROM users WHERE username = ?", username)
        .execute(&mut *transaction)
        .await;

    match result {
        Ok(deleted) => {
            if deleted.rows_affected() == 0 {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| Status::InternalServerError)?;
                return Err(Status::NotFound);
            }
            transaction
                .commit()
                .await
                .map_err(|_| Status::InternalServerError)?;

            if auth_user.username == username {
                if let Some(cookies) = cookies {
                    cookies.remove_private(Cookie::build("user_id"));
                }
            }
            Ok(Json(DeleteAccountResponse {
                message: format!("User {} deleted successfully", username),
            }))
        }
        Err(_) => {
            transaction
                .rollback()
                .await
                .map_err(|_| Status::InternalServerError)?;
            Err(Status::InternalServerError)
        }
    }
}

#[get("/users")]
pub async fn get_user_list(
    admin: AuthenticatedUser,
    db: &Db,
) -> Result<Json<Vec<UserInfo>>, Status> {
    // 관리자 권한 확인
    if !admin.is_admin {
        return Err(Status::Forbidden);
    }

    // 모든 사용자 정보 조회 (패스워드 포함)
    let users = sqlx::query!(
        r#"
        SELECT users.id, users.username, users.password, users.is_admin,
               features.gpt_writer, features.traffic_gen, features.add_buddy, features.like_comment,
               permissions.gpt_gen
        FROM users
        LEFT JOIN features ON users.id = features.user_id
        LEFT JOIN permissions ON users.id = permissions.user_id
        "#
    )
    .fetch_all(&**db)
    .await
    .map_err(|_| Status::InternalServerError)?;

    // 조회 결과를 UserInfo 구조체로 변환
    let user_list: Vec<UserInfo> = users
        .into_iter()
        .map(|user| UserInfo {
            id: user.id,
            username: user.username.unwrap_or_else(|| "Undefined".to_string()),
            password_hash: user.password.unwrap_or_else(|| "No password".to_string()),
            is_admin: user.is_admin.unwrap_or(false),
            features: Features {
                gpt_writer: user.gpt_writer.unwrap_or(false),
                traffic_gen: user.traffic_gen.unwrap_or(false),
                add_buddy: user.add_buddy.unwrap_or(false),
                like_comment: user.like_comment.unwrap_or(false),
            },
            permission: Permission {
                gpt_gen: user.gpt_gen.unwrap_or(false),
            },
        })
        .collect();

    Ok(Json(user_list))
}

#[post("/register", data = "<user>")]
pub async fn register(
    admin: AuthenticatedUser,
    user: Form<User>,
    db: &Db,
) -> Result<Json<RegisterResponse>, Status> {
    if !admin.is_admin {
        return Err(Status::Forbidden);
    }

    let mut transaction = db.begin().await.map_err(|_| Status::InternalServerError)?;

    let user = user.into_inner();

    let existing_user = sqlx::query!(
        "SELECT username FROM users WHERE username = ?",
        user.username
    )
    .fetch_optional(&**db)
    .await
    .map_err(|_| Status::InternalServerError)?;

    if existing_user.is_some() {
        // 이미 존재하는 사용자 이름인 경우
        return Err(Status::Conflict);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(user.password.as_bytes(), &salt)
        .map_err(|_| Status::InternalServerError)?
        .to_string();

    let user_id = sqlx::query!(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        user.username,
        password_hash,
        user.is_admin
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| Status::InternalServerError)?
    .last_insert_rowid();

    sqlx::query!(
        "INSERT INTO features (user_id, gpt_writer, traffic_gen, add_buddy, like_comment) VALUES (?, ?, ?, ?, ?)",
        user_id, user.features.gpt_writer, user.features.traffic_gen, user.features.add_buddy, user.features.like_comment
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| Status::InternalServerError)?;

    sqlx::query!(
        "INSERT INTO permissions (user_id, gpt_gen) VALUES (?, ?)",
        user_id,
        user.permission.gpt_gen
    )
    .execute(&mut *transaction)
    .await
    .map_err(|_| Status::InternalServerError)?;

    transaction
        .commit()
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(RegisterResponse {
        message: format!("User {} registered successfully", user.username),
    }))
}

#[post("/logout")]
pub fn logout(
    user: Option<AuthenticatedUser>,
    cookies: Option<&CookieJar<'_>>,
) -> Result<Json<LogoutResponse>, Status> {
    match user {
        Some(_) => {
            if let Some(cookies) = cookies {
                cookies.remove_private(Cookie::build("user_id"));
            }
            Ok(Json(LogoutResponse {
                message: "Logout successfully.".to_string(),
            }))
        }
        None => Err(Status::Unauthorized),
    }
}

#[post("/login", data = "<user>")]
pub async fn login(
    user: Form<User>,
    cookies: Option<&CookieJar<'_>>,
    db: &Db,
) -> Result<Json<LoginResponse>, Status> {
    let user = user.into_inner();

    // 사용자 이름 기반 로그인 시도 제한 확인
    if check_login_attempts(&user.username) {
        return Err(Status::TooManyRequests);
    }

    let db_user = sqlx::query!(
        "SELECT id, username, password, is_admin FROM users WHERE username = ?",
        user.username
    )
    .fetch_optional(&**db)
    .await
    .map_err(|_| Status::InternalServerError)?;

    if let Some(db_user) = db_user {
        let password = db_user.password.ok_or(Status::InternalServerError)?;

        let parsed_hash = PasswordHash::new(&password).map_err(|_| Status::InternalServerError)?;

        let argon2 = Argon2::default();
        if argon2
            .verify_password(user.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            reset_login_attempts(&user.username);

            let user_id = db_user.id.ok_or(Status::InternalServerError)?;
            if let Some(cookies) = cookies {
                let mut cookie = Cookie::new("user_id", generate_session_token(user_id));
                cookie.set_http_only(true);
                cookie.set_secure(true);
                cookie.set_same_site(SameSite::Strict);
                cookie.set_path("/");

                cookies.add_private(cookie.clone());
            } else {
                return Err(Status::InternalServerError);
            };

            // 사용자의 Features 와 Permission 정보를 가져옵니다.
            let features = sqlx::query_as!(FeaturesDB,
                "SELECT gpt_writer, traffic_gen, add_buddy, like_comment FROM features WHERE user_id = ?",
                user_id
            )
            .fetch_optional(&**db)
            .await
            .map_err(|_| Status::InternalServerError)?
            .map(Features::from);

            // 사용자의 Permission 정보를 가져옵니다.
            let permission = sqlx::query_as!(
                PermissionDB,
                "SELECT gpt_gen FROM permissions WHERE user_id = ?",
                user_id
            )
            .fetch_optional(&**db)
            .await
            .map_err(|_| Status::InternalServerError)?
            .map(Permission::from);

            Ok(Json(LoginResponse {
                message: "Login successful".to_string(),
                user_id: Some(user_id),
                username: Some(db_user.username.unwrap_or_default()),
                is_admin: db_user.is_admin,
                features,
                permission,
            }))
        } else {
            increment_login_attempts(&user.username);
            Err(Status::Unauthorized)
        }
    } else {
        increment_login_attempts(&user.username);
        Err(Status::Unauthorized)
    }
}

#[post("/validate_session", data = "<session_info>")]
pub async fn validate_session(
    session_info: Json<ValidateSessionRequest>,
    cookies: &CookieJar<'_>,
    db: &Db,
) -> Result<Json<ValidateSessionResponse>, Status> {
    let session_info = session_info.into_inner();

    // 사용자 ID 추출
    let user_id = match cookies.get_private("user_id"){
        Some(token) =>{
            match extract_user_id_from_token(token.value()){
                Some(id) => id,
                None => return Err(Status::InternalServerError),
            }
        },
        None => {
            return Err(Status::InternalServerError)
        },
    };

    // 데이터베이스에서 사용자 정보 조회
    let user = match sqlx::query!(
        "SELECT id, username FROM users WHERE id = ? AND username = ?",
        user_id,
        session_info.username
    )
    .fetch_optional(&**db)
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return Ok(Json(ValidateSessionResponse {
                is_valid: false,
                message: "User not found".to_string(),
            }))
        }
        Err(_) => return Err(Status::InternalServerError),
    };

    // 사용자 ID와 username이 일치하는지 확인
    if user.id != user_id as i64 || user.username.as_deref() != Some(&session_info.username) {
        return Err(Status::Unauthorized);
    }

    Ok(Json(ValidateSessionResponse {
        is_valid: true,
        message: "Session is valid".to_string(),
    }))
}

#[get("/get_proxy")]
pub async fn get_proxy(state: &State<Arc<Mutex<ServerState>>>) -> Result<Json<ProxyResponse>, Status> {
    Ok(Json(ProxyResponse {
        proxy_list: state.lock().await.cache.clone(),
    }))
}