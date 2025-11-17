mod types;
use actix_web::{get, web, HttpResponse, Scope};
use std::collections::HashMap;
use types::*;

pub fn sys_scope() -> Scope {
    web::scope("/sys").service(_get_sys_logs).service(_get_sys_logs_query)
}

/// GET /api/logs/sys
#[get("")]
async fn _get_sys_logs() -> HttpResponse {
    let mut logs = HashMap::new();
    logs.insert(
        "1".into(),
        SysLogEntry {
            month:     "Aug".into(),
            day:       30,
            time:      SysLogTime { hour: 12, min: 30 },
            direction: "A to B".into(),
            log_type:  "INFO".into(),
            messages:  "System started".into(),
        },
    );
    HttpResponse::Ok().json(SysLogsResponse { length: logs.len(), logs })
}

/// GET /api/logs/sys/query?Search=Month&Parameter=Aug
#[get("/query")]
async fn _get_sys_logs_query(query: web::Json<SysLogQuery>) -> HttpResponse {
    dbg!(&query);
    let mut logs = HashMap::new();
    logs.insert(
        "1".into(),
        SysLogEntry {
            month:     query.parameter.clone(),
            day:       30,
            time:      SysLogTime { hour: 13, min: 0 },
            direction: "A to B".into(),
            log_type:  "DEBUG".into(),
            messages:  "Filtered log".into(),
        },
    );
    HttpResponse::Ok().json(SysLogsResponse { length: logs.len(), logs })
}
