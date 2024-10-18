use rocket::response::Redirect;

use crate::types::AuthenticatedUser;

#[get("/login")]
pub fn login_page(user: Option<AuthenticatedUser>) -> Result<&'static str, Redirect> {
    match user {
        Some(_) => Err(Redirect::to("/")), // 이미 로그인된 경우 홈페이지로 리다이렉트
        None => Ok("Please login with POST /login"),
    }
}
