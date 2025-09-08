mod types;

use crate::commons::{ResponseResult, ResponseType};
use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{get, post, web, HttpResponse, Scope};
use std::collections::HashMap;
use types::*;

pub fn pdir_scope() -> Scope {
    web::scope("/pdir")
        .service(_get_pdir_pcs)
        .service(_get_pdir_one)
        .service(_post_pdir_action_upload)
        .service(_post_pdir_action_download)
}

/// GET /api/file/pdir/pcs
#[get("/pcs")]
async fn _get_pdir_pcs() -> HttpResponse {
    let mut map = HashMap::new();
    map.insert("uuid-1".into(), "host-a".into());
    map.insert("uuid-2".into(), "host-b".into());
    let body = PcsResponse { length: map.len(), pcs: map };
    HttpResponse::Ok().json(body)
}

/// GET /api/file/pdir/one
#[get("/one")]
async fn _get_pdir_one(data: web::Json<GetOneRequest>) -> HttpResponse {
    dbg!(&data);
    let mut files = HashMap::new();
    files.insert(
        "file1.txt".into(),
        FileEntry {
            size:     1.2,
            unit:     FileUnit::KB,
            owner:    "root".into(),
            mode:     "rw-r--r--".into(),
            modified: "2025-08-30T12:00:00Z".into(),
        },
    );
    let body = FilesResponse { length: files.len(), files };
    HttpResponse::Ok().json(body)
}

/// POST /api/file/pdir/action/upload
#[derive(Debug, MultipartForm)]
pub struct UploadForm {
    #[multipart(rename = "Uuid")]
    pub uuid: Text<String>,
    #[multipart(rename = "File")]
    pub file: Vec<TempFile>,
}

#[post("/action/upload")]
async fn _post_pdir_action_upload(
    MultipartForm(form): MultipartForm<UploadForm>,
) -> web::Json<ResponseResult> {
    dbg!(&form.uuid, &form.file.len());
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Uploaded".into() })
}

/// POST /api/file/pdir/action/download
#[post("/action/download")]
async fn _post_pdir_action_download(data: web::Json<DownloadRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Downloaded".into() })
}
