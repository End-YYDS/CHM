pub mod types;

use actix_web::{get, web, HttpResponse, Scope};
use types::*;

pub fn config_scope() -> Scope {
    web::scope("/config").service(_get_config_root)
}

/// GET /api/config/?Name=ReloadRate
#[get("")]
async fn _get_config_root(query: web::Json<GetConfigQuery>) -> HttpResponse {
    // TODO: 從 DB / 檔案 / env 取得真值
    let reload_rate = 1000_i64;

    match query.name.as_str() {
        "ReloadRate" => HttpResponse::Ok().json(ReloadRateResponse { reload_rate }),
        // 若未來支援回傳整份設定，可改成：
        // _ => HttpResponse::Ok().json(Config { reload_rate, ..Default::default() }),
        _ => HttpResponse::Ok().json(ReloadRateResponse { reload_rate }),
    }
}
