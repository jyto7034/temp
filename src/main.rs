use login_server::api::{delete_account, get_user_list, register, update_user};
use login_server::features::{add_buddy, gpt_writer, like_comment, traffic_gen};
use login_server::routes;
use login_server::server;
use login_server::types::{Db, Features, Permission, ServerState};
use login_server::utils::read_lines;
use rocket::routes;
use rocket_db_pools::Database;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::Mutex;

enum Command {
    Serve,
    AddUser {
        username: String,
        password: String,
        is_admin: bool,
        features: Features,
        permission: Permission,
    },
    UpdateUser {
        username: String,
        new_password: Option<String>,
        is_admin: Option<bool>,
        features: Option<Features>,
        permission: Option<Permission>,
    },
    DeleteUser {
        username: String,
    },
    ListUsers,
    Help,
    Quit,
}

fn parse_command(input: &str) -> Result<Command, String> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }

    match parts[0] {
        "serve" => Ok(Command::Serve),
        "add_user" => {
            if parts.len() < 3 {
                return Err("Usage: add_user <username> <password> [--is-admin] [--features <feature1,feature2,...>] [--permission <permission>]".to_string());
            }
            let username = parts[1].to_string();
            let password = parts[2].to_string();
            let mut is_admin = false;
            let mut features = Features {
                gpt_writer: false,
                traffic_gen: false,
                add_buddy: false,
                like_comment: false,
            };
            let mut permission = Permission { gpt_gen: false };
            let mut i = 3;
            while i < parts.len() {
                match parts[i] {
                    "--is-admin" => {
                        is_admin = true;
                        i += 1;
                    }
                    "--features" => {
                        if i + 1 < parts.len() {
                            let feature_list: Vec<&str> = parts[i + 1].split(',').collect();
                            features.gpt_writer = feature_list.contains(&"gpt_writer");
                            features.traffic_gen = feature_list.contains(&"traffic_gen");
                            features.add_buddy = feature_list.contains(&"add_buddy");
                            features.like_comment = feature_list.contains(&"like_comment");
                            i += 2;
                        } else {
                            return Err("Missing features".to_string());
                        }
                    }
                    "--permission" => {
                        if i + 1 < parts.len() {
                            permission.gpt_gen = parts[i + 1] == "gpt_gen";
                            i += 2;
                        } else {
                            return Err("Missing permission".to_string());
                        }
                    }
                    _ => return Err(format!("Unknown option: {}", parts[i])),
                }
            }
            Ok(Command::AddUser {
                username,
                password,
                is_admin,
                features,
                permission,
            })
        }
        "update_user" => {
            if parts.len() < 2 {
                return Err("Usage: update_user <username> [--new-password <new_password>] [--is-admin <true/false>] [--features <feature1,feature2,...>] [--permission <true/false>]".to_string());
            }
            let username = parts[1].to_string();
            let mut new_password = None;
            let mut is_admin = None;
            let mut features = None;
            let mut permission = None;
            let mut i = 2;
            while i < parts.len() {
                match parts[i] {
                    "--new-password" => {
                        if i + 1 < parts.len() {
                            new_password = Some(parts[i + 1].to_string());
                            i += 2;
                        } else {
                            return Err("Missing new password".to_string());
                        }
                    }
                    "--is-admin" => {
                        if i + 1 < parts.len() {
                            is_admin = Some(parts[i + 1].to_lowercase() == "true");
                            i += 2;
                        } else {
                            return Err("Missing is_admin value".to_string());
                        }
                    }
                    "--features" => {
                        if i + 1 < parts.len() {
                            let feature_list: Vec<&str> = parts[i + 1].split(',').collect();
                            features = Some(Features {
                                gpt_writer: feature_list.contains(&"gpt_writer"),
                                traffic_gen: feature_list.contains(&"traffic_gen"),
                                add_buddy: feature_list.contains(&"add_buddy"),
                                like_comment: feature_list.contains(&"like_comment"),
                            });
                            i += 2;
                        } else {
                            return Err("Missing features".to_string());
                        }
                    }
                    "--permission" => {
                        if i + 1 < parts.len() {
                            permission = Some(Permission {
                                gpt_gen: parts[i + 1].to_lowercase() == "true",
                            });
                            i += 2;
                        } else {
                            return Err("Missing permission".to_string());
                        }
                    }
                    _ => return Err(format!("Unknown option: {}", parts[i])),
                }
            }
            Ok(Command::UpdateUser {
                username,
                new_password,
                is_admin,
                features,
                permission,
            })
        }
        "delete_user" => {
            if parts.len() != 2 {
                return Err("Usage: delete_user <username>".to_string());
            }
            Ok(Command::DeleteUser {
                username: parts[1].to_string(),
            })
        }

        "list_users" => Ok(Command::ListUsers),
        "help" => Ok(Command::Help),
        "quit" => Ok(Command::Quit),
        _ => Err(format!("Unknown command: {}", parts[0])),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_list = match read_lines("proxy_list.txt") {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("Error reading proxy_list.txt: {}", e);
            vec![String::from("Failed to load proxy list")]
        }
    };

    let db_pool = SqlitePool::connect("sqlite:database.db").await?;
    let state = Arc::new(Mutex::new(ServerState {
        db: db_pool.clone(),
        shutdown: None,
        cache: proxy_list
    }));

    let server_state = state.clone();
    tokio::spawn(async move {
        let rocket = rocket::build()
            .mount(
                "/",
                routes![
                    server::update_user,
                    routes::login_page,
                    server::login,
                    server::register,
                    traffic_gen,
                    add_buddy,
                    gpt_writer,
                    like_comment,
                    server::delete_account,
                    server::get_user_list,
                    server::logout,
                    server::validate_session,
                    server::get_proxy,
                ],
            )
            .attach(Db::init())
            .manage(server_state)
            .ignite()
            .await?;

        rocket.launch().await
    });

    loop {
        let input = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_string()
        })
        .await?;

        let command = match parse_command(&input) {
            Ok(cmd) => cmd,
            Err(e) => {
                println!("Error: {}. Try 'help' for usage.", e);
                continue;
            }
        };

        match command {
            Command::Serve => println!("Server is already running."),
            Command::AddUser {
                username,
                password,
                is_admin,
                features,
                permission,
            } => {
                let state = state.lock().await;
                match register(
                    &state.db, username, password, is_admin, features, permission,
                )
                .await
                {
                    Ok(msg) => println!("{msg}"),
                    Err(e) => println!("Failed. {e}"),
                }
            }
            Command::UpdateUser {
                username,
                new_password,
                is_admin,
                features,
                permission,
            } => {
                let state = state.lock().await;
                match update_user(
                    &state.db,
                    &username,
                    new_password.clone(),
                    is_admin,
                    features.clone(),
                    permission.clone(),
                )
                .await
                {
                    Ok(_) => {
                        println!("User {} updated successfully.", username);
                        let mut updates = Vec::new();
                        if new_password.is_some() {
                            updates.push("password");
                        }
                        if is_admin.is_some() {
                            updates.push("admin status");
                        }
                        if features.is_some() {
                            updates.push("features");
                        }
                        if permission.is_some() {
                            updates.push("permissions");
                        }
                        if !updates.is_empty() {
                            println!("Updated: {}", updates.join(", "));
                        }
                    }
                    Err(e) => println!("Failed to update user: {}", e),
                }
            }
            Command::DeleteUser { username } => {
                let state = state.lock().await;
                match delete_account(&state.db, username.clone()).await {
                    Ok(_) => println!("User {} deleted successfully.", username),
                    Err(e) => println!("Failed to delete user: {}", e),
                }
            }
            Command::ListUsers => {
                let state = state.lock().await;
                match get_user_list(&state.db).await {
                    Ok(users) => {
                        println!("Users:");
                        for user in users {
                            println!("{:?}", user);
                        }
                    }
                    Err(e) => println!("Error listing users: {}", e),
                }
            }
            Command::Help => {
                println!("Available commands:");
                println!("  serve - Show server status");
                println!("  add_user <username> <password> [--is-admin] [--features <feature1,feature2,...>] [--permission <true/false>]");
                println!("    - Add a new user");
                println!("    - Features: gpt_writer, traffic_gen, add_buddy, like_comment");
                println!("    - Permission: gpt_gen");
                println!("    Example: add_user newuser password123 --is-admin --features gpt_writer,add_buddy --permission true");
                println!("  update_user <username> [--new-password <new_password>] [--is-admin <true/false>] [--features <feature1,feature2,...>] [--permission <true/false>]");
                println!("    - Update an existing user");
                println!("    Example: update_user user --new-password pass --features gpt_writer,add_buddy,traffic_gen --permission true");
                println!("  delete_user <username> - Delete a user");
                println!("  list_users - List all users");
                println!("  help - Show this help message");
                println!("  quit - Exit the program");
            }
            Command::Quit => {
                let mut state = state.lock().await;
                if let Some(shutdown) = state.shutdown.take() {
                    shutdown.notify();
                }
                println!("Shutting down server and exiting CLI...");
                break;
            }
        }
    }

    Ok(())
}
