use actix_web::{get, post, web, Scope};

use crate::{
    commons::{ResponseResult, ResponseType},
    handles::chm::mca::types::{get_revoked, get_valid, RevokeRequest, Revoked, Valid},
};

pub mod types;

pub fn mca_scope() -> Scope {
    web::scope("/mCA").service(valid).service(revoked).service(revoke)
}

#[get("/valid")]
async fn valid() -> web::Json<get_valid> {
    web::Json(get_valid {
        valid:  Valid {
            name:   "Example Name".into(),
            signer: "Example Signer".into(),
            period: "2023-01-01T00:00:00Z/2024-01-01T00:00:00Z".into(),
        },
        length: 1,
    })
}

#[get("/revoked")]
async fn revoked() -> web::Json<get_revoked> {
    web::Json(get_revoked {
        revoke: Revoked {
            number: "123".into(),
            time:   "2023-01-01T00:00:00Z".into(),
            reason: "No longer needed".into(),
        },
        length: 1,
    })
}

#[post("/revoke")]
async fn revoke(data: web::Json<RevokeRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Revoke endpoint hit".to_string(),
    })
}
