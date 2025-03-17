use totp_rs::TOTP;

pub fn make_totp(secret: Vec<u8>, id: String, username: String) -> TOTP {
    TOTP::new(
        totp_rs::Algorithm::SHA256,
        6,
        1,
        30,
        secret,
        Some("SSC Example App".to_string()),
        format!("{} - {}", username, id),
    )
    .unwrap()
}
