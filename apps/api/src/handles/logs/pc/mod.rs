mod types;
use actix_web::{get, web, HttpResponse, Scope};
use std::collections::HashMap;
use types::*;

pub fn pc_scope() -> Scope {
    web::scope("/pc").service(_get_pc_all).service(_get_pc_logs).service(_get_pc_logs_query)
}

/// GET /api/logs/pc/all
#[get("/all")]
async fn _get_pc_all() -> HttpResponse {
    let mut pcs = HashMap::new();
    pcs.insert("uuid-a".into(), "host-a".into());
    pcs.insert("uuid-b".into(), "host-b".into());
    HttpResponse::Ok().json(PcsResponse { length: pcs.len(), pcs })
}

/// GET /api/logs/pc
#[get("")]
async fn _get_pc_logs(query: web::Json<PcRequest>) -> HttpResponse {
    dbg!(&query);
    let mut logs = HashMap::new();
    logs.insert(
        "1".into(),
        PcLogEntry {
            month:    "Aug".into(),
            day:      30,
            time:     "12:34".into(),
            hostname: query.uuid.clone(),
            log_type: "WARN".into(),
            messages: "High CPU usage".into(),
        },
    );
    HttpResponse::Ok().json(PcLogsResponse { length: logs.len(), logs })
}

/// GET /api/logs/pc/query
#[get("/query")]
async fn _get_pc_logs_query(query: web::Json<PcLogQuery>) -> HttpResponse {
    dbg!(&query);
    let mut logs = HashMap::new();
    logs.insert(
        "1".into(),
        PcLogEntry {
            month:    "Aug".into(),
            day:      30,
            time:     "13:45".into(),
            hostname: query.uuid.clone(),
            log_type: query.parameter.clone(),
            messages: "Filtered PC log".into(),
        },
    );
    HttpResponse::Ok().json(PcLogsResponse { length: logs.len(), logs })
}
