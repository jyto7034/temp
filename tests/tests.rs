#[cfg(test)]
mod tests {
    use login_server::api;
    use login_server::types::{Db, Features, Permission, User, UserUpdateInfo};
    use login_server::utils::read_lines;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;
    use rocket::routes;
    use rocket::serde::json::json;
    use rocket_db_pools::Database;
    use sqlx::sqlite::SqlitePoolOptions;
    use sqlx::SqlitePool;
    use std::thread;
    use std::time::Duration;

    async fn setup_test_db() -> SqlitePool {
        let db_url = "sqlite::memory:";
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_url)
            .await
            .expect("Failed to create test database pool");

        // 테스트용 테이블 생성
        sqlx::query(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                is_admin BOOLEAN NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create users table");

        sqlx::query(
            "CREATE TABLE features (
                user_id INTEGER PRIMARY KEY,
                gpt_writer BOOLEAN NOT NULL DEFAULT 0,
                traffic_gen BOOLEAN NOT NULL DEFAULT 0,
                add_buddy BOOLEAN NOT NULL DEFAULT 0,
                like_comment BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create features table");

        sqlx::query(
            "CREATE TABLE permissions (
                user_id INTEGER PRIMARY KEY,
                gpt_gen BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create permissions table");

        pool
    }

    fn setup() -> Client {
        let rocket = rocket::build().attach(Db::init()).mount(
            "/",
            routes![
                login_server::server::login,
                login_server::server::logout,
                login_server::server::register,
                login_server::server::delete_account,
                login_server::server::get_user_list,
                login_server::server::update_user
            ],
        );
        Client::tracked(rocket).expect("valid rocket instance")
    }

    // test_function-name_success/failure_reason

    #[test]
    fn test_login_success() {
        let client = setup();
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_login_failure() {
        let client = setup();
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=wrongpass")
            .dispatch();
        assert_eq!(response.status(), Status::Unauthorized);
    }

    #[test]
    fn test_logout() {
        let client = setup();
        // 어드민 로그인
        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 로그아웃
        let response = client.post("/logout").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_register() {
        let client = setup();
        // 관리자로 로그인 (실제 환경에 맞게 조정 필요)
        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=newuser&password=newpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let response = client.post("/delete_account/newuser").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_register_failure_conflict() {
        let client = setup();
        // 관리자로 로그인
        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 임시 계정 생성
        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=newuser&password=newpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 동일한 ID 의 임시 계정 생성
        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=newuser&password=newpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Conflict);

        let response = client.post("/delete_account/newuser").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_delete_account_by_admin() {
        let client = setup();
        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 먼저 사용자 생성
        client.post("/register")
            .header(ContentType::Form)
            .body("username=deleteuser&password=deletepass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();

        // 계정 삭제
        let response = client.post("/delete_account/deleteuser").dispatch();
        assert_eq!(response.status(), Status::Ok); // 따로 Status::Ok 하지 않아도 알아서 리턴 함
    }

    #[test]
    fn test_get_user_list() {
        let client = setup();
        // 관리자로 로그인
        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        let response = client.get("/users").dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.into_string().unwrap();
        assert!(body.contains("username"));
        assert!(body.contains("is_admin"));
    }

    #[test]
    fn test_login_attempt_limit() {
        let client = setup();

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 테스트용 사용자 등록
        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=testuser&password=testpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 잘못된 비밀번호로 최대 시도 횟수만큼 로그인 시도
        for _ in 0..5 {
            let response = client
                .post("/login")
                .header(ContentType::Form)
                .body("username=testuser&password=wrongpass")
                .dispatch();
            assert_eq!(response.status(), Status::Unauthorized);
        }

        // 다음 로그인 시도는 너무 많은 요청으로 인해 실패해야 함
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=testuser&password=wrongpass")
            .dispatch();
        assert_eq!(response.status(), Status::TooManyRequests);

        thread::sleep(Duration::from_secs(2));

        // 올바른 비밀번호로 로그인 시도 ( 해제 되어있어야함 )
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=testuser&password=testpass")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 테스트 사용자 삭제
        let response = client.post("/delete_account/testuser").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_login_reset_after_success() {
        let client = setup();

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 테스트용 사용자 등록
        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=testuser2&password=testpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 잘못된 비밀번호로 4번 로그인 시도
        for _ in 0..4 {
            let response = client
                .post("/login")
                .header(ContentType::Form)
                .body("username=testuser2&password=wrongpass")
                .dispatch();
            assert_eq!(response.status(), Status::Unauthorized);
        }

        // 올바른 비밀번호로 로그인 성공
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=testuser2&password=testpass")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 로그인 성공 후 다시 5번 잘못된 비밀번호로 로그인 시도 (카운터가 리셋되어야 함)
        for _ in 0..5 {
            let response = client
                .post("/login")
                .header(ContentType::Form)
                .body("username=testuser2&password=wrongpass")
                .dispatch();
            assert_eq!(response.status(), Status::Unauthorized);
        }

        // 6번째 시도는 TooManyRequests 여야 함
        let response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=testuser2&password=wrongpass")
            .dispatch();
        assert_eq!(response.status(), Status::TooManyRequests);

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 테스트 사용자 삭제
        let response = client.post("/delete_account/testuser2").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[test]
    fn test_update_user() {
        let client = setup();

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 일반 사용자 등록
        let response = client.post("/register")
            .header(ContentType::Form)
            .body("username=newuser&password=newpass&is_admin=false&features.gpt_writer=true&features.traffic_gen=false&features.add_buddy=true&features.like_comment=false&permission.gpt_gen=true")
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // 사용자 정보 업데이트
        let update_response = client
            .put("/update_user")
            .header(ContentType::JSON)
            .body(
                json!({
                    "username": "newuser",
                    "is_admin": false,
                    "features": {
                        "gpt_writer": true,
                        "traffic_gen": false,
                        "add_buddy": true,
                        "like_comment": false
                    },
                    "permission": {
                        "gpt_gen": true
                    }
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(update_response.status(), Status::Ok);

        // 관리자 로그아웃
        client.post("/logout").dispatch();

        // 일반 사용자로 로그인
        let user_login_response = client
            .post("/login")
            .header(ContentType::Form)
            .body("username=newuser&password=newpass")
            .dispatch();
        assert_eq!(user_login_response.status(), Status::Ok);

        // 일반 사용자가 업데이트 시도 (실패해야 함)
        let unauthorized_update = client
            .put("/update_user")
            .header(ContentType::JSON)
            .body(
                json!({
                    "username": "newuser",
                    "is_admin": false
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(unauthorized_update.status(), Status::Forbidden);

        println!("Entry");

        client
            .post("/login")
            .header(ContentType::Form)
            .body("username=admin&password=admin")
            .dispatch();

        // 존재하지 않는 사용자 업데이트 시도
        let not_found_update = client
            .put("/update_user")
            .header(ContentType::JSON)
            .body(
                json!({
                    "username": "nonexistent",
                    "is_admin": true
                })
                .to_string(),
            )
            .dispatch();
        assert_eq!(not_found_update.status(), Status::NotFound);

        let response = client.post("/delete_account/newuser").dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn test_api_register() {
        let pool = setup_test_db().await;
        let db = Db(pool);

        let user = User {
            username: "testuser".to_string(),
            password: "testpassword".to_string(),
            is_admin: false,
            features: Features {
                gpt_writer: true,
                traffic_gen: false,
                add_buddy: true,
                like_comment: false,
            },
            permission: Permission { gpt_gen: true },
        };

        let result = api::register(
            &db,
            user.username,
            user.password,
            user.is_admin,
            user.features,
            user.permission,
        )
        .await;

        assert!(result.is_ok());
    }

    #[rocket::async_test]
    async fn test_api_update_user() {
        let pool = setup_test_db().await;
        let db = Db(pool);

        // 먼저 사용자를 등록합니다
        let user = User {
            username: "testuser".to_string(),
            password: "testpassword".to_string(),
            is_admin: false,
            features: Features::default(),
            permission: Permission::default(),
        };
        api::register(
            &db,
            user.username,
            user.password,
            user.is_admin,
            user.features,
            user.permission,
        )
        .await
        .expect("Failed to register user");

        // 사용자 정보를 업데이트합니다
        let update_info = UserUpdateInfo {
            username: "testuser".to_string(),
            password: Some("newpassword".to_string()),
            is_admin: Some(true),
            features: Some(Features {
                gpt_writer: true,
                traffic_gen: true,
                add_buddy: false,
                like_comment: true,
            }),
            permission: Some(Permission { gpt_gen: true }),
        };

        let result = api::update_user(
            &db,
            &update_info.username,
            update_info.password,
            update_info.is_admin,
            update_info.features,
            update_info.permission,
        )
        .await;

        assert!(result.is_ok());
    }

    #[rocket::async_test]
    async fn test_api_delete_account() {
        let pool = setup_test_db().await;
        let db = Db(pool);

        // 먼저 사용자를 등록합니다
        let user = User {
            username: "testuser".to_string(),
            password: "testpassword".to_string(),
            is_admin: false,
            features: Features::default(),
            permission: Permission::default(),
        };
        api::register(
            &db,
            user.username.clone(),
            user.password,
            user.is_admin,
            user.features,
            user.permission,
        )
        .await
        .expect("Failed to register user");

        // 사용자 계정을 삭제합니다
        let result = api::delete_account(&db, user.username).await;

        assert!(result.is_ok());
    }

    #[rocket::async_test]
    async fn test_api_get_user_list() {
        let pool = setup_test_db().await;
        let db = Db(pool);

        // 몇 명의 사용자를 등록합니다
        for i in 1..=3 {
            let user = User {
                username: format!("testuser{}", i),
                password: "testpassword".to_string(),
                is_admin: false,
                features: Features::default(),
                permission: Permission::default(),
            };
            api::register(
                &db,
                user.username.clone(),
                user.password,
                user.is_admin,
                user.features,
                user.permission,
            )
            .await
            .expect("Failed to register user");
        }

        // 사용자 목록을 가져옵니다
        let result = api::get_user_list(&db).await;

        assert!(result.is_ok());
        if let Ok(users) = result {
            assert_eq!(users.len(), 3);
        }
    }

    #[test]
    fn get_proxy_test() {
        let d = read_lines("proxy_list.txt").unwrap();
        println!("{:?}", d);
    }
}
