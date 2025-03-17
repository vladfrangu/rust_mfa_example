use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, UNIX_EPOCH},
};

use actix_web::{App, HttpResponse, HttpServer, middleware, web};
use env_logger::Env;
use snowflake::SnowflakeIdGenerator;
use totp_rs::{Secret, TOTP};

mod routes;
mod totp;

#[derive(Debug, serde::Serialize, Clone)]
struct TwoFactorState {
    enabled: bool,
    // TODO: technically this should get encrypted somehow, for the purpose of this example it will be "plain text"
    secret: String,
    qr_code_url: String,
    terminal_qr_code: String,
}

#[derive(Debug, serde::Serialize)]
struct User {
    id: String,
    username: String,
    password_hash: String,
    two_factor_state: TwoFactorState,
    // Serde should omit this
    #[serde(skip_serializing)]
    totp: TOTP,
}

impl User {
    fn new(id: String, username: String, password_hash: String) -> Self {
        let secret = Secret::generate_secret();

        let totp = totp::make_totp(secret.to_bytes().unwrap(), id.clone(), username.clone());
        let qrcode_url = totp.get_url();

        // For google authenticator
        let qrcode = qrcode::QrCode::new(qrcode_url.as_str()).unwrap();
        let qr_code_string = qrcode.render::<qrcode::render::unicode::Dense1x2>().build();

        let two_factor_state = TwoFactorState {
            enabled: false,
            secret: secret.to_encoded().to_string(),
            qr_code_url: qrcode_url,
            terminal_qr_code: qr_code_string,
        };

        Self {
            id,
            username,
            password_hash,
            two_factor_state,
            totp,
        }
    }

    fn from_user(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            username: user.username.clone(),
            password_hash: user.password_hash.clone(),
            two_factor_state: user.two_factor_state.clone(),
            totp: user.totp.clone(),
        }
    }
}

struct AppState {
    users: Mutex<HashMap<String, User>>,
    sessions: Mutex<HashMap<String, Vec<String>>>,
    id_generator: Mutex<SnowflakeIdGenerator>,
    argon2: Mutex<argon2::Argon2<'static>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        users: Mutex::new(HashMap::new()),
        // Epoch is 2025-01-01T00:00:00
        id_generator: Mutex::new(SnowflakeIdGenerator::with_epoch(
            1,
            1,
            UNIX_EPOCH + Duration::from_millis(1735689600000),
        )),
        argon2: Mutex::new(argon2::Argon2::default()),
        sessions: Mutex::new(HashMap::new()),
    });

    println!("Server running at http://localhost:8080");

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(middleware::Logger::default())
            // This is just for debugging purposes, no real service would have a blanket "list all user ids and usernames" route without checks in place
            .route(
                "/api/users",
                web::get().to(async |state: web::Data<AppState>| {
                    let users = state.users.lock().unwrap();
                    let users: Vec<&User> = users.values().collect();

                    #[derive(serde::Serialize)]
                    struct CleanUser {
                        id: String,
                        username: String,
                        two_factor_enabled: bool,
                    }

                    let users: Vec<CleanUser> = users
                        .iter()
                        .map(|user| CleanUser {
                            id: user.id.clone(),
                            username: user.username.clone(),
                            two_factor_enabled: user.two_factor_state.enabled,
                        })
                        .collect();

                    HttpResponse::Ok().json(users)
                }),
            )
            // and this is a disgrace and should not be done in any api EVER
            .route(
                "/api/internal/list_all_users",
                web::get().to(async |state: web::Data<AppState>| {
                    let users = state.users.lock().unwrap();
                    let sessions = state.sessions.lock().unwrap();
                    let users: Vec<&User> = users.values().collect();

                    #[derive(serde::Serialize)]
                    struct DetailedUser {
                        user: User,
                        sessions: Vec<String>,
                    }

                    let detailed_users: Vec<DetailedUser> = users
                        .iter()
                        .map(|user| DetailedUser {
                            user: User::from_user(user),
                            sessions: sessions.get(&user.id).unwrap_or(&vec![]).clone(),
                        })
                        .collect();

                    HttpResponse::Ok().json(detailed_users)
                }),
            )
            // Should have ratelimits on all these routes but this is, again, an example project
            .route(
                "/api/users",
                web::post().to(routes::users::create_user::handler),
            )
            .route(
                "/api/users/verify-2fa-setup",
                web::post().to(routes::users::verify_2fa::handler),
            )
            .route("/api/login", web::post().to(routes::users::login::handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
