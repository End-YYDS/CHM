mod types;

use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::{delete, get, post, put, web, HttpResponse, Scope};

use crate::commons::{ResponseResult, ResponseType};
use std::collections::HashMap;
use types::*;

pub fn cron_scope() -> Scope {
    web::scope("/cron")
        .service(_get_cron_all)
        .service(_post_cron_root)
        .service(_delete_cron_root)
        .service(_put_cron_root)
        .service(_post_cron_action_import)
        .service(_post_cron_action_export)
}

/// GET /api/cron/all
#[get("/all")]
async fn _get_cron_all() -> HttpResponse {
    // Demo 資料；實作時可改讀系統 crontab/DB
    let mut jobs = HashMap::new();
    jobs.insert(
        "id01".to_string(),
        CronJobEntry {
            name:     "backup".into(),
            command:  "/usr/local/bin/backup.sh".into(),
            schedule: Schedule { minute: 0, hour: 3, date: 1, month: 1, week: 0 },
            username: "root".into(),
        },
    );
    jobs.insert(
        "id02".to_string(),
        CronJobEntry {
            name:     "rotate".into(),
            command:  "/usr/sbin/logrotate /etc/logrotate.conf".into(),
            schedule: Schedule { minute: 0, hour: 0, date: 0, month: 0, week: 1 },
            username: "root".into(),
        },
    );
    let body = GetAllResponse { length: jobs.len(), jobs };
    HttpResponse::Ok().json(body)
}

/// POST /api/cron
#[post("")]
async fn _post_cron_root(data: web::Json<CreateCronRequest>) -> web::Json<ResponseResult> {
    // 實作新增：寫入 DB / 轉寫 crontab
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Cron job created".into() })
}

/// DELETE /api/cron
#[delete("")]
async fn _delete_cron_root(data: web::Json<DeleteCronRequest>) -> web::Json<ResponseResult> {
    // 實作刪除：依 id 移除
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Cron job deleted".into() })
}

/// PUT /api/cron
#[put("")]
async fn _put_cron_root(data: web::Json<PutCronRequest>) -> web::Json<ResponseResult> {
    // 實作更新：用 id 覆蓋整筆
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Cron jobs updated".into() })
}

/// 匯入：POST /api/cron/action/import
#[derive(Debug, MultipartForm)]
struct ImportForm {
    // 規格為 { file }：名稱用 file
    #[multipart(rename = "File")]
    pub file: TempFile,
}

#[post("/action/import")]
async fn _post_cron_action_import(
    MultipartForm(form): MultipartForm<ImportForm>,
) -> web::Json<ResponseResult> {
    // 實作：解析檔案 → 轉為 cron 內容並寫入
    dbg!(&form.file);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Imported".into() })
}

/// 匯出：POST /api/cron/action/export
#[post("/action/export")]
async fn _post_cron_action_export() -> web::Json<ResponseResult> {
    // 規格希望回傳 { Type, Message: file }。
    // 這裡示範回傳一個「可由前端另取」的檔名/URL；若你要直接送檔案下載，改成回傳
    // Binary/Attachment。
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "crontab_export.txt".into(), // 或 data:URL / 簽名下載URL
    })
}
