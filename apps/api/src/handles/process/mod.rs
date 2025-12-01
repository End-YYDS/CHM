mod types;

use actix_web::{get, post, web, HttpResponse, Scope};
use std::collections::HashMap;

use crate::commons::{ResponseResult, ResponseType};
use types::*;

pub fn process_scope() -> Scope {
    web::scope("/process")
        .service(_get_process_all) // GET  /api/process/all
        .service(_post_process_one) // POST /api/process/one
        .service(_post_process_action_start) // POST /api/process/action/start
        .service(_post_process_action_stop) // POST /api/process/action/stop
        .service(_post_process_action_restart)
        .service(_post_process_action_enable)
        .service(_post_process_action_disable)
        .service(_post_process_action_start_enable)
        .service(_post_process_action_stop_disable)
}

/// GET /api/process/all
#[get("/all")]
async fn _get_process_all() -> HttpResponse {
    // demo：請替換為實際資料來源
    let mut proc_map = HashMap::new();
    proc_map.insert("nginx".into(), ProcessEntry { status: true, boot: true });
    proc_map.insert("redis".into(), ProcessEntry { status: true, boot: false });
    let pc = PcProcess { hostname: "node-a".into(), process: proc_map, length: 2 };

    let mut pcs = HashMap::new();
    pcs.insert("uuid-a".into(), pc);

    HttpResponse::Ok().json(GetAllProcessResponse { pcs, length: 1 })
}

/// POST /api/process/one
#[post("/one")]
async fn _post_process_one(data: web::Json<OneProcessRequest>) -> HttpResponse {
    dbg!(&data);
    // demo：回傳指定 Uuid 的進程
    let mut proc_map = HashMap::new();
    proc_map.insert("nginx".into(), ProcessEntry { status: true, boot: true });
    proc_map.insert("redis".into(), ProcessEntry { status: false, boot: false });

    HttpResponse::Ok()
        .json(OneProcessResponse { process: proc_map.clone(), length: proc_map.len() })
}

/// POST /api/process/action/start
#[post("/action/start")]
async fn _post_process_action_start(data: web::Json<ActionRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Process started".into() })
}

/// POST /api/process/action/stop
#[post("/action/stop")]
async fn _post_process_action_stop(data: web::Json<ActionRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Process stopped".into() })
}

/// POST /api/process/action/restart
#[post("/action/restart")]
async fn _post_process_action_restart(data: web::Json<ActionRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "Process restarted".into() })
}

/// POST /api/process/action/enable
#[post("/action/enable")]
async fn _post_process_action_enable(data: web::Json<ActionRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Process enabled at boot".into(),
    })
}

/// POST /api/process/action/disable
#[post("/action/disable")]
async fn _post_process_action_disable(data: web::Json<ActionRequest>) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Process disabled at boot".into(),
    })
}

/// POST /api/process/action/start_enable
#[post("/action/start_enable")]
async fn _post_process_action_start_enable(
    data: web::Json<ActionRequest>,
) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Process started & enabled".into(),
    })
}

/// POST /api/process/action/stop_disable
#[post("/action/stop_disable")]
async fn _post_process_action_stop_disable(
    data: web::Json<ActionRequest>,
) -> web::Json<ResponseResult> {
    dbg!(&data);
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "Process stopped & disabled".into(),
    })
}
