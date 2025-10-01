use actix_web::{get, post, web};

use crate::{
    commons::{
        error_logs::{Error_log, Level},
        CommonInfo, Date, ResponseResult, ResponseType, Status, Time, UuidRequest,
    },
    handles::server::ftp::{
        logs::{
            acc_log::{Access_log, Action},
            Logs,
        },
        session::{
            login_time::{Login_Time, Month},
            transfer::{Transfer, TransferType},
            Sessions,
        },
        types::FTPResponse,
    },
};

mod logs;
mod session;
mod types;

#[get("")]
async fn ftp_root(data: web::Json<UuidRequest>) -> web::Json<FTPResponse> {
    dbg!(data);
    web::Json(generate_test_ftp_response())
}

fn generate_test_ftp_response() -> FTPResponse {
    FTPResponse {
        common_info: CommonInfo {
            hostname: "ftp-server-01".to_string(),
            status:   Status::Active,
            cpu:      15.2,
            memory:   4096.0,
        },
        connections: 25,
        sessions:    Sessions {
            ip:          "192.168.1.101".to_string(),
            username:    "user1".to_string(),
            login_time:  Login_Time {
                year:  2025,
                month: Month::Aug,
                day:   22,
                hour:  14,
                min:   45,
            },
            current_dir: "/home/user1".to_string(),
            status:      crate::handles::server::ftp::session::Status::Uploading,
            transfer:    Transfer {
                transfer_type: TransferType::Upload,
                file:          "example.txt".to_string(),
                size:          2048,
                speed:         1024,
            },
        },
        logs:        Logs {
            error_log:  vec![Error_log {
                date:    Date {
                    year:  2025,
                    month: crate::commons::Month::Aug,
                    day:   22,
                    week:  crate::commons::Week::Fri,
                    time:  Time { hour: 14, min: 30 },
                },
                module:  "auth".to_string(),
                level:   Level::error,
                pid:     5678,
                client:  "192.168.1.102:21".to_string(),
                message: "Authentication failed for user 'user2'".to_string(),
            }],
            errlength:  1,
            access_log: vec![Access_log {
                ip:       "192.168.1.103".to_string(),
                date:     Date {
                    year:  2025,
                    month: crate::commons::Month::Aug,
                    day:   22,
                    week:  crate::commons::Week::Fri,
                    time:  Time { hour: 14, min: 50 },
                },
                username: "user3".to_string(),
                action:   Action::Download,
                file:     "report.pdf".to_string(),
                size:     5120,
                status:   crate::handles::server::ftp::logs::acc_log::Status::Success,
            }],
            acclength:  1,
        },
    }
}

pub fn ftp_scope() -> actix_web::Scope {
    actix_web::web::scope("/ftp").service(ftp_root).service(action_scope())
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
