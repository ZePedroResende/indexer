use super::error::{Error, Result};
use crate::api::auth::signature::check_type_data;
use crate::db::Db;
use actix_jwt_auth_middleware::TokenSigner;
use actix_web::{
    get, post,
    web::{self, Json},
    HttpResponse, Responder,
};
use chrono::Duration;
use color_eyre::eyre::eyre;

use crate::api::User;
use ethers_core::types::Address;
use jwt_compact::alg::Ed25519;
use serde::{Deserialize, Serialize};

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok()
}

#[derive(Debug, Deserialize)]
struct Register {
    address: alloy_primitives::Address,
}

#[post("/register")]
async fn register(db: web::Data<Db>, Json(register): Json<Register>) -> Result<impl Responder> {
    db.register(register.address.into()).await?;

    Ok(HttpResponse::Ok())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    signature: String,
    address: Address,
    current_timestamp: u64,
    expiration_timestamp: u64,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
}

#[post("/auth")]
async fn auth(
    cookie_signer: web::Data<TokenSigner<User, Ed25519>>,
    Json(auth): Json<AuthRequest>,
) -> Result<impl Responder> {
    check_type_data(
        &auth.signature,
        auth.address,
        auth.current_timestamp,
        auth.expiration_timestamp,
    )?;

    let user = User { id: auth.address };

    let access_token = cookie_signer
        .create_header_value(
            &user,
            Duration::seconds(auth.expiration_timestamp as i64 - auth.current_timestamp as i64),
        )
        .map_err(|e| Error::Generic(eyre!("Failed to create access token: {}", e)))?
        .to_str()
        .map_err(|e| Error::Generic(eyre!("Failed to create access token: {}", e)))?
        .to_string();

    let refresh_token = cookie_signer
        .create_refresh_header_value(&user)
        .map_err(|e| Error::Generic(eyre!("Failed to create refresh token: {}", e)))?
        .to_str()
        .map_err(|e| Error::Generic(eyre!("Failed to create access token: {}", e)))?
        .to_string();

    let auth_response = AuthResponse {
        access_token,
        refresh_token,
    };

    let json = serde_json::to_string(&auth_response).map_err(|_| eyre!("Failed to serialize"))?;
    Ok(HttpResponse::Ok().body(json))
}
