use actix_web::{get, post, web};

use crate::{
    commons::{
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::squid::{
        logs::{acc_log::Access_log, Logs},
        types::SquidResponse,
    },
};

mod logs;
mod types;

#[get("")]
async fn squid_root(data: web::Json<UuidRequest>) -> web::Json<SquidResponse> {
    dbg!(data);
    web::Json(generate_test_squid_response())
}

fn generate_test_squid_response() -> SquidResponse {
    SquidResponse {
        common:             CommonInfo {
            hostname: "Squid Proxy Server".to_string(),
            status:   Status::Active,
            cpu:      23.5,
            memory:   8.2,
        },
        connections:        10,
        cache_hits:         5,
        cache_misses:       2,
        requests_processed: 20,
        logs:               Logs {
            access_log:        vec![Access_log {
                ip:           "192.168.1.100".to_string(),
                date:         Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   22,
                    week:  Week::Fri,
                    time:  Time { hour: 12, min: 34 },
                },
                method:       "GET".to_string(),
                url:          "http://example.com/test".to_string(),
                status:       200,
                bytes_served: 1024,
                referer:      "https://referer.com".to_string(),
                user_agent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            }],
            access_log_length: 1,
        },
    }
}

pub fn squid_scope() -> actix_web::Scope {
    web::scope("/squid").service(squid_root).service(action_scope())
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
