use actix_web::{HttpResponse, Responder, web};
use argon2::{PasswordHash, PasswordVerifier};
use base64::Engine;
use rand::distr::{Alphanumeric, Distribution};

use crate::AppState;

fn string_to_base64(input: &str) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(input)
}

// Technically should use JWT or similar but 🤷
fn generate_random_string(length: usize) -> String {
    let mut rng = rand::rng();
    let random_string: String = Alphanumeric
        .sample_iter(&mut rng)
        .take(length)
        .map(char::from)
        .collect();

    random_string
}

#[derive(serde::Serialize)]
pub struct LoginJSONResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct LoginJSONBody {
    username: String,
    password: String,
    two_factor_code: String,
}

pub async fn handler(data: web::Data<AppState>, req: web::Json<LoginJSONBody>) -> impl Responder {
    let users = data.users.lock().unwrap();

    // Check if user exists
    if let Some(user) = users
        .values()
        .find(|u| u.username.eq_ignore_ascii_case(&req.username))
    {
        // Verify password first
        let is_password_valid = data
            .argon2
            .lock()
            .unwrap()
            .verify_password(
                req.password.bytes().collect::<Vec<_>>().as_slice(),
                &PasswordHash::new(&user.password_hash).unwrap(),
            )
            .map(|_| true)
            .unwrap_or(false);

        if !is_password_valid {
            return HttpResponse::Unauthorized().json(LoginJSONResponse {
                success: false,
                message: Some("Invalid credentials".to_string()),
                session_token: None,
                user_id: None,
            });
        }

        if !user.two_factor_state.enabled {
            return HttpResponse::Unauthorized().json(LoginJSONResponse {
                success: false,
                message: Some("2FA is not enabled".to_string()),
                session_token: None,
                user_id: None,
            });
        }

        if !user
            .totp
            .check_current(&req.two_factor_code)
            .unwrap_or(false)
        {
            return HttpResponse::Unauthorized().json(LoginJSONResponse {
                success: false,
                message: Some("Invalid 2FA code".to_string()),
                session_token: None,
                user_id: None,
            });
        }

        // this random code should be marked as used somewhere and not reused for a bit of time but /shrug

        let random_string = generate_random_string(64);
        let session_token = format!("{}.{}", string_to_base64(&user.id), random_string);

        let mut sessions = data.sessions.lock().unwrap();

        if let Some(existing_sessions) = sessions.get_mut(&user.id) {
            existing_sessions.push(session_token.clone());
        } else {
            sessions.insert(user.id.clone(), vec![session_token.clone()]);
        }

        HttpResponse::Ok().json(LoginJSONResponse {
            success: true,
            message: None,
            user_id: Some(user.id.clone()),
            session_token: Some(session_token),
        })
    } else {
        HttpResponse::NotFound().json(LoginJSONResponse {
            success: false,
            message: Some("User not found".to_string()),
            user_id: None,
            session_token: None,
        })
    }
}
