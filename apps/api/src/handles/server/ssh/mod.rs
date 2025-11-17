use actix_web::{get, post, web};

use crate::{
    commons::{
        CommonInfo, Date, Month, ResponseResult, ResponseType, Status, Time, UuidRequest, Week,
    },
    handles::server::ssh::{
        last_login::Last_Login,
        logs::{
            auth_log::{Action, Auth_Log},
            Logs,
        },
        types::SSHResponse,
    },
};

mod last_login;
mod logs;
mod types;

#[get("")]
async fn ssh_root(data: web::Json<UuidRequest>) -> web::Json<SSHResponse> {
    dbg!(data);
    web::Json(generate_test_ssh_response())
}

fn generate_test_ssh_response() -> SSHResponse {
    SSHResponse {
        common:      CommonInfo {
            hostname: "SSH Server".to_string(),
            status:   Status::Active,
            cpu:      12.3,
            memory:   4.5,
        },
        connections: 3,
        last_login:  Last_Login {
            user: "alice".to_string(),
            date: Date {
                year:  2025,
                month: Month::Aug,
                day:   22,
                week:  Week::Fri,
                time:  Time { hour: 9, min: 15 },
            },
            ip:   "192.168.1.101".to_string(),
        },
        logs:        Logs {
            auth_log:        vec![Auth_Log {
                date:    Date {
                    year:  2025,
                    month: Month::Aug,
                    day:   22,
                    week:  Week::Fri,
                    time:  Time { hour: 8, min: 55 },
                },
                user:    "bob".to_string(),
                action:  Action::login,
                result:  crate::handles::server::ssh::logs::auth_log::Result::success,
                ip:      "192.168.1.102".to_string(),
                message: "Login successful".to_string(),
            }],
            auth_log_length: 1,
        },
    }
}

pub fn ssh_scope() -> actix_web::Scope {
    actix_web::web::scope("/ssh").service(ssh_root).service(action_scope())
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
