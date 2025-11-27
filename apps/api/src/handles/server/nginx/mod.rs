use actix_web::{get, post, web};

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::nginx::{
        connections::Connections,
        logs::{acc_log::Access_log, Error_log_extensive, Logs},
        types::NginxResponse,
    },
};

mod connections;
mod logs;
mod types;

#[get("")]
async fn nginx_root(data: web::Json<UuidRequest>) -> web::Json<NginxResponse> {
    dbg!(data);
    web::Json(generate_test_nginx_response())
}

/// 產生測試用 NginxResponse 資料
fn generate_test_nginx_response() -> NginxResponse {
    NginxResponse {
        common_info: CommonInfo {
            hostname: "nginx-server-01".to_string(),
            status:   Status::Active,
            cpu:      1.5,
            memory:   256.0,
            ip:       None,
        },
        connections: Connections { active: 100, accepted: 5000, handled: 5000, requests: 15000 },
        logs:        Logs {
            error_log:  vec![Error_log_extensive {
                worker_id: 1,
                error_log: Error_log {
                    date:    Date {
                        year:  2025,
                        month: Month::Aug,
                        day:   19,
                        week:  Week::Tue,
                        time:  Time { hour: 14, min: 30 },
                    },
                    module:  "nginx".to_string(),
                    level:   Level::error,
                    pid:     1234,
                    client:  "192.168.1.100".to_string(),
                    message: "Failed to open configuration file".to_string(),
                },
            }],
            errlength:  1,
            access_log: vec![Access_log {
                ip:                     "192.168.1.200".to_string(),
                date:                   Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   19,
                    week:  Week::Tue,
                    time:  Time { hour: 16, min: 10 },
                },
                method:                 "GET".to_string(),
                url:                    "/index.html".to_string(),
                protocol:               "HTTP/1.1".to_string(),
                status:                 200,
                byte:                   1024,
                referer:                "http://example.com".to_string(),
                user_agent:             "Mozilla/5.0".to_string(),
                upstream:               "127.0.0.1:8080".to_string(),
                request_time:           0.123,
                upstream_response_time: 0.120,
            }],
            acclength:  1,
        },
    }
}

pub fn nginx_scope() -> actix_web::Scope {
    actix_web::web::scope("/nginx").service(nginx_root).service(action_scope())
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
