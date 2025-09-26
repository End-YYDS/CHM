use crate::{
    auth::RequireLogin,
    commons::{ResponseResult, ResponseType},
};
use actix_session::Session;
use actix_web::{post, web};

#[post("")]
async fn logout(_auth: RequireLogin, session: Session) -> web::Json<ResponseResult> {
    session.purge();
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Logout successful".to_string(),
    })
}

pub fn logout_scope() -> actix_web::Scope {
    web::scope("/logout").service(logout)
}
