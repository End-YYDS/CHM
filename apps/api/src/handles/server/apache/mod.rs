#![allow(unused)]
use actix_web::{get, post, web};
use serde::{Deserialize, Serialize};

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::apache::{logs::Logs, types::ApacheResponse},
};

mod logs;
mod types;

#[get("")]
async fn apache_root(web::Query(data): web::Query<UuidRequest>) -> web::Json<ApacheResponse> {
    tracing::debug!(?data, "Parsed UuidRequest from query");
    web::Json(generate_test_apache_response())
}

fn generate_test_apache_response() -> ApacheResponse {
    use crate::handles::server::apache::logs::{access_log::Access_log, Logs};
    ApacheResponse {
        common_info: CommonInfo {
            hostname: "localhost".to_string(),
            status: Status::Active,
            cpu: 1.5,
            memory: 256.0,
        },
        connections: 100,
        logs: Logs {
            error_log: vec![Error_log {
                date: Date {
                    year: 2025,
                    month: Month::Aug,
                    day: 19,
                    week: Week::Tue,
                    time: Time { hour: 12, min: 0 },
                },
                module: "core".to_string(),
                level: Level::info,
                pid: 1234,
                client: "127.0.0.1:54321".to_string(),
                message: "No errors".to_string(),
            }],
            errlength: 1,
            access_log: vec![Access_log {
                ip: "127.0.0.1".to_string(),
                date: Date {
                    year: 2025,
                    month: Month::Aug,
                    day: 19,
                    week: Week::Tue,
                    time: Time { hour: 12, min: 0 },
                },
                method: "GET".to_string(),
                url: "/index.html".to_string(),
                protocol: "HTTP/1.1".to_string(),
                status: 200,
                byte: 1024,
                referer: "-".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
            }],
            acclength: 1,
        },
    }
}

pub fn apache_scope() -> actix_web::Scope {
    web::scope("/apache").service(apache_root).service(action_scope())
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
        r#type: ResponseType::Ok,
        message: "restart successful".to_string(),
    })
}
