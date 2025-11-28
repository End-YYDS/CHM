use crate::{
    auth::RequireLogin,
    commons::{ResponseResult, ResponseType},
};
use actix_session::Session;
use actix_web::{post, web};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(logout),
    tags(
        (name = "Auth", description = "登入/ 登出 / 身分驗證相關 API")
    )
)]
pub struct LogoutApiDocs;

#[utoipa::path(
    post,
    path = "/logout",
    tag = "Auth",
    responses(
        (status = 200, description = "登出成功", body = ResponseResult,example = json!({
                "Type": "Ok",
                "Message": "Login successful"
            })),
        (status = 500, description = "伺服器錯誤", body = ResponseResult,example = json!({
                "Type": "Err",
                "Message": "Internal Server Error"
            })),
    )
)]
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
