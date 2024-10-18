use rocket::{http::CookieJar, response::Redirect};

#[get("/traffic_gen")]
pub fn traffic_gen(cookies: &CookieJar<'_>) -> Result<&'static str, Redirect> {
    if cookies.get_private("user_id").is_some() {
        Ok("Welcome to your dashboard!")
    } else {
        Err(Redirect::to("/login"))
    }
}

#[get("/like_comment")]
pub fn like_comment(cookies: &CookieJar<'_>) -> Result<&'static str, Redirect> {
    if cookies.get_private("user_id").is_some() {
        Ok("Welcome to your dashboard!")
    } else {
        Err(Redirect::to("/login"))
    }
}

#[get("/add_buddy")]
pub fn add_buddy(cookies: &CookieJar<'_>) -> Result<&'static str, Redirect> {
    if cookies.get_private("user_id").is_some() {
        Ok("Welcome to your dashboard!")
    } else {
        Err(Redirect::to("/login"))
    }
}

#[get("/gpt_writer")]
pub fn gpt_writer(cookies: &CookieJar<'_>) -> Result<&'static str, Redirect> {
    if cookies.get_private("user_id").is_some() {
        Ok("Welcome to your dashboard!")
    } else {
        Err(Redirect::to("/login"))
    }
}
