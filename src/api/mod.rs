mod auth;
mod error;
mod routes;

use crate::{config::HttpConfig, db::Db};
use actix_cors::Cors;
use actix_jwt_auth_middleware::use_jwt::UseJWTOnApp;
use actix_jwt_auth_middleware::{AuthResult, Authority, FromRequest, TokenSigner};
use actix_web::{web, App, HttpServer};
use ethers_core::types::Address;
use exonum_crypto::KeyPair;
use jwt_compact::alg::Ed25519;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::instrument;
use tracing_actix_web::TracingLogger;
#[derive(Serialize, Deserialize, Debug, Clone, FromRequest)]
struct User {
    id: Address,
}

#[instrument(name = "api", skip(db, config), fields(port = config.port))]
pub fn start(db: Db, config: HttpConfig) -> JoinHandle<Result<(), std::io::Error>> {
    let key_pair = KeyPair::random();
    let server = HttpServer::new(move || {
        let authority = Authority::<User, Ed25519, _, _>::new()
            .enable_cookie_tokens(false)
            .enable_header_tokens(true)
            .refresh_authorizer(|| async move { Ok(()) })
            .token_signer(Some(
                TokenSigner::new()
                    .signing_key(key_pair.secret_key().clone())
                    .algorithm(Ed25519)
                    .build()
                    .expect(""),
            ))
            .verifying_key(key_pair.public_key())
            .build()
            .expect("");

        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(TracingLogger::default())
            .service(routes::health)
            .service(routes::auth)
            .use_jwt(authority, web::scope("").service(routes::register))
            .app_data(web::Data::new(db.clone()))
    })
    .bind(("0.0.0.0", config.port))
    .unwrap();

    tokio::spawn(server.run())
}
