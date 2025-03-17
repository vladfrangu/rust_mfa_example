use actix_web::{HttpResponse, Responder, web};

use crate::AppState;

#[derive(serde::Deserialize)]
pub struct Verify2FaJSONBody {
    id: String,
    code: String,
}

#[derive(serde::Serialize)]
pub struct Verify2FaJSONResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub async fn handler(
    data: web::Data<AppState>,
    req: web::Json<Verify2FaJSONBody>,
) -> impl Responder {
    let mut users = data.users.lock().unwrap();

    if let Some(user) = users.get_mut(&req.id) {
        if user.two_factor_state.enabled {
            return HttpResponse::BadRequest().json(Verify2FaJSONResponse {
                success: false,
                message: Some("2FA is already enabled".to_string()),
            });
        }

        if user.totp.check_current(&req.code).unwrap_or(false) {
            user.two_factor_state.enabled = true;

            HttpResponse::Ok().json(Verify2FaJSONResponse {
                success: true,
                message: None,
            })
        } else {
            HttpResponse::BadRequest().json(Verify2FaJSONResponse {
                success: false,
                message: Some("Invalid 2FA code".to_string()),
            })
        }
    } else {
        HttpResponse::BadRequest().json(Verify2FaJSONResponse {
            success: false,
            message: Some("User not found".to_string()),
        })
    }
}
