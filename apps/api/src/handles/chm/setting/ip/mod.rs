mod types;

use actix_web::{delete, get, post, put, web, HttpResponse, Scope};

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn ip_scope() -> Scope {
    web::scope("/ip")
        .service(_get_ip_root)
        .service(_post_ip_root)
        .service(_delete_ip_root)
        .service(_put_ip_root)
}

/// GET /api/chm/setting/ip
#[get("")]
async fn _get_ip_root() -> HttpResponse {
    let body = GetIpResponse { mode: Mode::None, lists: None };
    HttpResponse::Ok().json(body)
}

/// POST /api/chm/setting/ip
#[post("")]
async fn _post_ip_root(data: web::Json<PostIpRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "IP added".into() })
}

/// DELETE /api/chm/setting/ip
#[delete("")]
async fn _delete_ip_root(data: web::Json<DeleteIpRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "IP deleted".into() })
}

/// PUT /api/chm/setting/ip
#[put("")]
async fn _put_ip_root(data: web::Json<PutIpRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Mode switched".into() })
}
