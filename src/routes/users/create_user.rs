use actix_web::{HttpResponse, Responder, web};

use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};

use crate::{AppState, User};

#[derive(serde::Deserialize)]
pub struct CreateUserJSONBody {
    username: String,
    password: String,
}

#[derive(serde::Serialize)]
struct CreateUser2FaSetupJSONBody {
    secret_key: String,
    qr_code: String,
    ascii_qr_code: String,
}

#[derive(serde::Serialize)]
pub struct CreateUserJSONResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_factor_setup_data: Option<CreateUser2FaSetupJSONBody>,
}

// Technically you want to also check that a password hasn't been pwnd before, but this is just an example project
fn validate_password(password: &str) -> bool {
    password.len() >= 8
        && password.chars().any(char::is_uppercase)
        && password.chars().any(char::is_lowercase)
        && password.chars().any(char::is_numeric)
        && password.chars().any(|c| "!@#$%^&*()".contains(c))
}

pub async fn handler(
    data: web::Data<AppState>,
    req: web::Json<CreateUserJSONBody>,
) -> impl Responder {
    let mut users = data.users.lock().unwrap();

    if users
        .values()
        .any(|u| u.username.eq_ignore_ascii_case(&req.username))
    {
        return HttpResponse::BadRequest().json(CreateUserJSONResponse {
            message: Some("Username already exists".to_string()),
            success: false,
            user_id: None,
            two_factor_setup_data: None,
        });
    }

    if !validate_password(&req.password) {
        return HttpResponse::BadRequest().json(CreateUserJSONResponse {
            message: Some("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character".to_string()),
            success: false,
            user_id: None,
            two_factor_setup_data: None,
        });
    }

    println!("Creating user with username: {}", req.username);

    let id = data
        .id_generator
        .lock()
        .unwrap()
        .real_time_generate()
        .to_string();

    println!("Generated ID: {}", id);

    // Hash the password with argon2
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = data
        .argon2
        .lock()
        .unwrap()
        .hash_password(req.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user = User::new(id.clone(), req.username.clone(), password_hash);

    let two_fa_state = user.two_factor_state.clone();

    users.insert(id.clone(), user);

    HttpResponse::Ok().json(CreateUserJSONResponse {
        success: true,
        message: None,
        user_id: Some(id),
        two_factor_setup_data: Some(CreateUser2FaSetupJSONBody {
            secret_key: two_fa_state.secret.clone(),
            qr_code: two_fa_state.qr_code_url.clone(),
            ascii_qr_code: two_fa_state.terminal_qr_code.clone(),
        }),
    })
}
