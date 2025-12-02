use crate::commons::{Date, Month, ResponseResult, ResponseType, Time, Week};
use actix_web::{get, post, web, Scope};

mod types;
pub use types::{
    BackupRequest, BackupResponse, GetBackupsRequest, GetBackupsResponse, InnerGetBackupResponse,
    ReductionRequest,
};
use utoipa::OpenApi;
// const BACKUP_DIR: &str = "/var/chm/backups"; // 依你環境調整
//
// // === Utils ===
//
// fn make_backup_id(name: &str) -> String {
//     // 例: myname-2025-08-27T13-50-03Z
//     let ts = Utc::now().format("%Y-%m-%dT%H-%M-%SZ");
//     format!("{name}-{ts}")
// }
//
// fn backup_path_for(id: &str) -> PathBuf {
//     Path::new(BACKUP_DIR).join(format!("{id}.tar.zst"))
// }
//
// /// 實際做備份（demo：把字串寫成檔案；你改成真正的封裝/壓縮邏輯）
// /// 回傳：本地備份檔路徑
// async fn create_local_backup(id: &str) -> std::io::Result<PathBuf> {
//     use tokio::{fs, io::AsyncWriteExt};
//     let path = backup_path_for(id);
//     if let Some(parent) = path.parent() {
//         fs::create_dir_all(parent).await?;
//     }
//     let mut f = fs::File::create(&path).await?;
//     // 實務上：把資料庫/設定檔/憑證等打包後寫入
//     f.write_all(b"backup payload demo\n").await?;
//     f.flush().await?;
//     Ok(path)
// }
//
// // === Handlers ===
//
// async fn _post_backup_root(data: web::Json<BackupRequest>) ->
// web::Json<BackupResponse> {     let name = data.name.trim();
//     let loc = &data.r#type;
//
//     match loc {
//         BackupLocation::Local => {
//             let id = make_backup_id(name);
//             match create_local_backup(&id).await {
//                 Ok(_path) => {
//                     web::Json(BackupResponse {
//                         inner:        ResponseResult {
//                             r#type:  ResponseType::Ok,
//                             message: "Backup created".into(),
//                         },
//                         id:           Some(id.clone()),
//                         download_url:
// Some(format!("/api/chm/backup/{id}/file")),                         //
// 如果你要同時回傳檔名/MIME 也可以在這裡加欄位                     })
//                 }
//                 Err(e) => web::Json(BackupResponse {
//                     inner:        ResponseResult {
//                         r#type:  ResponseType::Err,
//                         message: format!("Backup failed: {e}"),
//                     },
//                     id:           None,
//                     download_url: None,
//                 }),
//             }
//         }
//         BackupLocation::Remote => {
//             // 在這裡做遠端備份（例如上傳 S3 / 另一台備援機）
//             // 假裝成功
//             web::Json(BackupResponse {
//                 inner:        ResponseResult {
//                     r#type:  ResponseType::Ok,
//                     message: "Remote backup triggered".into(),
//                 },
//                 id:           None,
//                 download_url: None,
//             })
//         }
//     }
// }

#[derive(OpenApi)]
#[openapi(
    paths(post_backup_root, get_backup_root, post_reduction),
    tags(
        (name = "Backup", description = "CHM 備份相關 API")
    )
)]
pub struct BackupApiDoc;

#[utoipa::path(
    post,
    path = "/chm/backup",
    tag = "Backup",
    request_body = BackupRequest,
    responses(
        (status = 200, body = BackupResponse),
    )
)]
#[post("")]
async fn post_backup_root(data: web::Json<BackupRequest>) -> web::Json<BackupResponse> {
    println!("{data:#?}");
    let is_local = matches!(data.r#type, types::BackupLocation::Local);
    web::Json(BackupResponse {
        inner:        ResponseResult {
            r#type:  ResponseType::Ok,
            message: "Backup endpoint hit".to_string(),
        },
        id:           if is_local { Some("ksdkkdskk".to_string()) } else { None },
        download_url: if is_local { Some("/api/chm/backup/123/file".to_string()) } else { None },
    })
}

#[utoipa::path(
    get,
    path = "/chm/backup",
    tag = "Backup",
    request_body = GetBackupsRequest,
    responses(
        (status = 200, body = GetBackupsResponse),
    )
)]
#[get("")]
async fn get_backup_root(data: web::Json<GetBackupsRequest>) -> web::Json<GetBackupsResponse> {
    dbg!(data);
    let backups = vec![InnerGetBackupResponse {
        name:  "Test1".to_string(),
        inner: Date {
            year:  2025,
            month: Month::Jan,
            day:   20,
            week:  Week::Mon,
            time:  Time { hour: 16, min: 40 },
        },
    }];
    let length = backups.len();
    web::Json(GetBackupsResponse { backups, length })
}

// #[get("/backup/{id}/file")]
// async fn download_backup(req: HttpRequest) -> Result<NamedFile, Error> {
//     let id: String = req.match_info().query("id").parse()?;
//     let path = backup_path_for(&id);
//
//     let mut nf = NamedFile::open_async(path).await?;
//     nf = nf.set_content_disposition(ContentDisposition {
//         disposition: DispositionType::Attachment,
//         parameters:
// vec![DispositionParam::Filename(format!("{id}.tar.zst"))],     });
//     Ok(nf)
// }

#[utoipa::path(
    post,
    path = "/chm/backup/reduction",
    tag = "Backup",
    request_body = ReductionRequest,
    responses(
        (status = 200, body = ResponseResult),
    )
)]
#[post("/reduction")]
async fn post_reduction(data: web::Json<ReductionRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Reduction endpoint hit".to_string(),
    })
}

pub fn backup_scope() -> Scope {
    web::scope("/backup").service(post_backup_root).service(get_backup_root).service(post_reduction)
    // .service(download_backup) // GET /api/chm/backup/{id}/file
}
