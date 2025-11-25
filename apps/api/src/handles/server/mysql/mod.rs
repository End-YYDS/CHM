use actix_web::{get, post, web};

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::mysql::{
        logs::{
            query_log::{Query_Type, Query_log},
            Logs,
        },
        types::MySQLResponse,
    },
};

mod logs;
mod types;

#[get("")]
async fn mysql_root(data: web::Json<UuidRequest>) -> web::Json<MySQLResponse> {
    dbg!(data);
    web::Json(generate_test_mysql_response())
}

/// 產生測試用 MySQLResponse 資料
fn generate_test_mysql_response() -> MySQLResponse {
    MySQLResponse {
        common_info:     CommonInfo {
            hostname: "mysql-server-01".to_string(),
            status:   Status::Active,
            cpu:      2.3,
            memory:   512.0,
            ip:       None,
        },
        connections:     120,
        databases:       8,
        queries_per_sec: 150.5,
        logs:            Logs {
            log_count:   vec![Error_log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 16, min: 20 },
                },
                module:  "query".to_string(),
                level:   Level::info,
                pid:     4321,
                client:  "192.168.1.210".to_string(),
                message: "Query executed".to_string(),
            }],
            errlength:   1,
            query_log:   vec![Query_log {
                ip:            "192.168.1.211".to_string(),
                date:          Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 16, min: 21 },
                },
                user:          "admin".to_string(),
                database:      "test_db".to_string(),
                query:         "SELECT * FROM users".to_string(),
                query_type:    Query_Type::SELECT,
                duration_ms:   25,
                status:        crate::handles::server::mysql::logs::query_log::Status::Success,
                affected_rows: 10,
            }],
            querylength: 1,
        },
    }
}

pub fn mysql_scope() -> actix_web::Scope {
    actix_web::web::scope("/mysql").service(mysql_root).service(action_scope())
}

fn action_scope() -> actix_web::Scope {
    web::scope("/action").service(action_start).service(action_stop).service(action_restart)
}

#[post("/start")]
async fn action_start(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "start successful".to_string() })
}

#[post("/stop")]
async fn action_stop(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult { r#type: ResponseType::Ok, message: "stop successful".to_string() })
}

#[post("/restart")]
async fn action_restart(data: web::Json<UuidRequest>) -> web::Json<ResponseResult> {
    println!("{data:#?}");
    web::Json(ResponseResult {
        r#type:  ResponseType::Ok,
        message: "restart successful".to_string(),
    })
}
