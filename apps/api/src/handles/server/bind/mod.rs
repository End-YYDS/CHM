mod logs;
mod queries;
mod types;

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::bind::{
        logs::{
            query_log::{QueryType, Query_log},
            Logs,
        },
        queries::Queries,
        types::BindResponse,
    },
};
use actix_web::{get, post, web};

#[get("")]
async fn bind_root(_data: web::Json<UuidRequest>) -> web::Json<BindResponse> {
    let test_date = BindResponse {
        common_info: CommonInfo {
            hostname: "bind-server-01".to_string(),
            status:   Status::Active,
            cpu:      2.5,
            memory:   512.0,
        },
        connections: 42,
        queries:     Queries { total: 1000, success: 950, nxdomain: 30, refused: 20 },
        logs:        Logs {
            error_log: vec![Error_log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 14, min: 30 },
                },
                module:  "resolver".to_string(),
                level:   Level::warn,
                pid:     4321,
                client:  "192.168.1.100:5353".to_string(),
                message: "Zone transfer failed".to_string(),
            }],
            errlength: 1,
            query_log: vec![Query_log {
                client:   "192.168.1.101:5353".to_string(),
                date:     Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 14, min: 31 },
                },
                query:    "example.com".to_string(),
                r#type:   QueryType::A,
                response: "93.184.216.34".to_string(),
                status:   crate::handles::server::bind::logs::query_log::Status::NOERROR,
                duration: 12.5,
            }],
            qrylength: 1,
        },
    };
    web::Json(test_date)
}

pub fn bind_scope() -> actix_web::Scope {
    actix_web::web::scope("/bind").service(bind_root).service(action_scope())
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
