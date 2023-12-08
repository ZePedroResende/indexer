use super::error::Result;
use crate::api::auth::signature::check_type_data;
use crate::db::Db;
use actix_web::{
    get, post,
    web::{self, Json},
    HttpResponse, Responder,
};

use ethers_core::types::Address;
use serde::Deserialize;

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
struct Auth {
    signature: String,
    address: Address,
    current_timestamp: u64,
    expiration_timestamp: u64,
}

#[post("/auth")]
async fn auth(db: web::Data<Db>, Json(auth): Json<Auth>) -> Result<impl Responder> {
    check_type_data(
        &auth.signature,
        auth.address,
        auth.current_timestamp,
        auth.expiration_timestamp,
    )?;
    Ok(HttpResponse::Ok())
}
