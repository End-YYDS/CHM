mod types;

use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::{get, post, web, HttpResponse, Scope};

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn vdir_scope() -> Scope {
    web::scope("/vdir")
        .service(_get_vdir_root)
        .service(_post_vdir_action_upload)
        .service(_post_vdir_action_download)
}

/// GET /api/file/vdir
#[get("")]
async fn _get_vdir_root() -> HttpResponse {
    let body = VdirResponse { path: "/virtual/storage".into() };
    HttpResponse::Ok().json(body)
}

/// POST /api/file/vdir/action/upload
#[derive(Debug, MultipartForm)]
pub struct UploadForm {
    #[multipart(rename = "File")]
    pub file: Vec<TempFile>,
}

#[post("/action/upload")]
async fn _post_vdir_action_upload(
    MultipartForm(form): MultipartForm<UploadForm>,
) -> web::Json<ResponseResult> {
    dbg!(&form.file.len());
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Vdir uploaded".into() })
}

/// POST /api/file/vdir/action/download
#[post("/action/download")]
async fn _post_vdir_action_download(data: web::Json<DownloadRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Vdir downloaded".into() })
}
