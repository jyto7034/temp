use crate::types::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

// 로그인 시도 확인 및 제한 함수
pub fn check_login_attempts(username: &str) -> bool {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let attempt = attempts
        .entry(username.to_string())
        .or_insert(LoginAttempt {
            count: 0,
            last_attempt: Instant::now(),
        });

    if attempt.count >= MAX_LOGIN_ATTEMPTS {
        if attempt.last_attempt.elapsed() < LOCKOUT_DURATION {
            return true; // 잠금 상태
        } else {
            attempt.count = 0; // 잠금 시간이 지났으면 초기화
        }
    }

    false // 제한되지 않음
}

// 로그인 시도 횟수 증가 함수
pub fn increment_login_attempts(username: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let attempt = attempts
        .entry(username.to_string())
        .or_insert(LoginAttempt {
            count: 0,
            last_attempt: Instant::now(),
        });
    attempt.count += 1;
    attempt.last_attempt = Instant::now();
}

// 로그인 시도 횟수 초기화 함수
pub fn reset_login_attempts(username: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    attempts.remove(username);
}

pub fn generate_session_token(user_id: i64) -> String {
    use rand::Rng;
    let random_bytes: [u8; 16] = rand::thread_rng().gen();
    let token = format!("{}_{}", user_id, hex::encode(random_bytes));
    token
}

pub fn extract_user_id_from_token(token: &str) -> Option<i64> {
    token
        .split('_')
        .next()
        .and_then(|id_str| id_str.parse().ok())
}

pub fn read_lines(filename: &str) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    reader.lines().collect()
}
